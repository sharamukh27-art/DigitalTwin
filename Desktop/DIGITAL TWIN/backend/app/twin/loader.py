"""Import a twin from a JSON or YAML file and export it back in the same shape.

Import is all-or-nothing: every validation error is collected first and nothing is
written unless the file is fully valid.
"""

import json
import logging
from collections import Counter
from pathlib import PurePath
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from app.controls import repository as control_repository
from app.core.errors import Conflict
from app.models.asset import Asset, AssetCreate
from app.models.control import Placement, SecurityControl, placement_errors
from app.models.link import Link
from app.models.network import Network, NetworkCreate
from app.models.twin_io import (
    ImportControl,
    ImportLink,
    ImportPlacement,
    ImportResult,
    NetworkFile,
)
from app.twin import repository
from app.twin.versioning import bump_version

logger = logging.getLogger(__name__)

_JSON_SUFFIXES = {".json"}
_YAML_SUFFIXES = {".yaml", ".yml"}


def _parse_file(file_bytes: bytes, filename: str) -> tuple[Any, list[str]]:
    """Decode the file into Python data. Returns (data, errors)."""
    suffix = PurePath(filename).suffix.lower()
    if suffix not in _JSON_SUFFIXES | _YAML_SUFFIXES:
        return None, [f"unsupported file type '{suffix or filename}': use .json or .yaml"]
    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None, ["file is not valid UTF-8 text"]
    try:
        data = json.loads(text) if suffix in _JSON_SUFFIXES else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        return None, [f"file could not be parsed: {exc}"]
    return data, []


def _model_errors(prefix: str, exc: ValidationError) -> list[str]:
    """Turn a Pydantic error into one readable message per failing field."""
    messages: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "value"
        messages.append(f"{prefix}: {location}: {error['msg']}")
    return messages


def _label(section: str, index: int, raw: Any) -> str:
    """Build an error prefix such as `assets[3] (WS-01)`."""
    code = raw.get("code") if isinstance(raw, dict) else None
    return f"{section}[{index}] ({code})" if isinstance(code, str) and code else f"{section}[{index}]"


def _raw_text(raw: Any, key: str) -> str | None:
    """Return a stripped string field of a raw entry, or None."""
    value = raw.get(key) if isinstance(raw, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _duplicates(values: list[str]) -> list[str]:
    """Return the values that occur more than once, sorted."""
    return sorted(value for value, count in Counter(values).items() if count > 1)


def _section(data: dict[str, Any], key: str, errors: list[str]) -> list[Any]:
    """Return a top-level list section, recording an error when it is not a list."""
    value = data.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"'{key}' must be a list")
        return []
    return value


def _validate_models(
    section: str, entries: list[Any], model: type[BaseModel], errors: list[str]
) -> list[Any]:
    """Validate each raw entry against a model, collecting every error."""
    valid: list[Any] = []
    for index, raw in enumerate(entries):
        try:
            valid.append(model.model_validate(raw))
        except ValidationError as exc:
            errors.extend(_model_errors(_label(section, index, raw), exc))
    return valid


def validate_file(
    file_bytes: bytes, filename: str, require_network: bool = True
) -> tuple[NetworkFile | None, list[str]]:
    """Validate an import file without touching the database.

    Returns the parsed file and an empty list when it is valid, otherwise None and
    every error found. With require_network=False the `network` section is ignored.
    """
    data, errors = _parse_file(file_bytes, filename)
    if errors:
        return None, errors
    if not isinstance(data, dict):
        return None, ["top level must be an object with keys: network, assets, links"]

    network = NetworkCreate(name="imported")
    if require_network:
        raw_network = data.get("network")
        if raw_network is None:
            errors.append("'network' section is required")
        else:
            try:
                network = NetworkCreate.model_validate(raw_network)
            except ValidationError as exc:
                errors.extend(_model_errors("network", exc))

    raw_assets = _section(data, "assets", errors)
    raw_links = _section(data, "links", errors)
    raw_controls = _section(data, "controls", errors)
    assets: list[AssetCreate] = _validate_models("assets", raw_assets, AssetCreate, errors)
    links: list[ImportLink] = _validate_models("links", raw_links, ImportLink, errors)
    controls: list[ImportControl] = _validate_models(
        "controls", raw_controls, ImportControl, errors
    )

    asset_codes = [code for raw in raw_assets if (code := _raw_text(raw, "code"))]
    for code in _duplicates(asset_codes):
        errors.append(f"duplicate asset code '{code}'")
    for ip in _duplicates([ip for raw in raw_assets if (ip := _raw_text(raw, "ip"))]):
        errors.append(f"duplicate IP address '{ip}' in the same network")
    for code in _duplicates([code for raw in raw_links if (code := _raw_text(raw, "code"))]):
        errors.append(f"duplicate link code '{code}'")
    for code in _duplicates([code for raw in raw_controls if (code := _raw_text(raw, "code"))]):
        errors.append(f"duplicate control code '{code}'")

    known_codes = set(asset_codes)
    for index, raw in enumerate(raw_links):
        label = _label("links", index, raw)
        source = _raw_text(raw, "source")
        target = _raw_text(raw, "target")
        for role, code in (("source", source), ("target", target)):
            if code is not None and code not in known_codes:
                errors.append(f"{label}: {role} references missing asset code '{code}'")
        if source is not None and source == target:
            errors.append(f"{label}: self-link, source and target are both '{source}'")

    for index, raw in enumerate(raw_controls):
        placement = raw.get("placement") if isinstance(raw, dict) else None
        referenced = placement.get("asset_codes") if isinstance(placement, dict) else None
        for code in referenced if isinstance(referenced, list) else []:
            if isinstance(code, str) and code.strip() not in known_codes:
                errors.append(
                    f"{_label('controls', index, raw)}: placement references "
                    f"missing asset code '{code.strip()}'"
                )
    for control in controls:
        placement = control.placement
        for message in placement_errors(
            placement.kind, placement.asset_codes, placement.zones, placement.services
        ):
            errors.append(f"control '{control.code}': {message}")

    if errors:
        return None, errors
    return NetworkFile(network=network, assets=assets, links=links, controls=controls), []


async def import_network(
    file_bytes: bytes, filename: str, network_id: str | None = None
) -> ImportResult:
    """Import a twin file.

    With `network_id` the assets, links and controls are loaded into that existing network,
    which must be empty (Conflict otherwise) and the file's `network` section is
    ignored. Without it a new network is created from the file.

    Returns an ImportResult. If `errors` is not empty nothing was written.
    """
    if network_id is not None:
        await repository.get_network(network_id)
        if (
            await repository.count_assets(network_id)
            or await repository.count_links(network_id)
            or await control_repository.count_controls(network_id)
        ):
            raise Conflict(
                "Network is not empty: import is only allowed into an empty network",
                {"network_id": network_id},
            )

    parsed, errors = validate_file(file_bytes, filename, require_network=network_id is None)
    if parsed is None:
        logger.info("import rejected", extra={"import_filename": filename, "errors": len(errors)})
        return ImportResult(errors=errors)

    created_network = network_id is None
    target_id = network_id
    try:
        if target_id is None:
            network = await repository.insert_network(Network(**parsed.network.model_dump()))
            target_id = network.id
        assets = [Asset(network_id=target_id, **asset.model_dump()) for asset in parsed.assets]
        ids_by_code = {asset.code: asset.id for asset in assets}
        links = [
            Link(
                network_id=target_id,
                source_asset_id=ids_by_code[link.source],
                target_asset_id=ids_by_code[link.target],
                **link.model_dump(exclude={"source", "target"}),
            )
            for link in parsed.links
        ]
        controls = [
            SecurityControl(
                network_id=target_id,
                placement=Placement(
                    kind=control.placement.kind,
                    asset_ids=[ids_by_code[code] for code in control.placement.asset_codes],
                    zones=control.placement.zones,
                    services=control.placement.services,
                ),
                **control.model_dump(exclude={"placement"}),
            )
            for control in parsed.controls
        ]
        await repository.insert_assets(assets)
        await repository.insert_links(links)
        await control_repository.insert_controls(controls)
        if not created_network:
            await bump_version(target_id)
    except Exception:
        if target_id is not None:
            await repository.delete_network_contents(target_id)
            if created_network:
                await repository.remove_network_document(target_id)
        logger.exception("import failed and was rolled back", extra={"import_filename": filename})
        raise

    logger.info(
        "import completed",
        extra={
            "network_id": target_id,
            "assets": len(assets),
            "links": len(links),
            "controls": len(controls),
        },
    )
    return ImportResult(
        network_id=target_id,
        assets_created=len(assets),
        links_created=len(links),
        controls_created=len(controls),
    )


async def export_network(network_id: str) -> NetworkFile:
    """Export a network in the import file shape. Raises NotFound for unknown ids."""
    network = await repository.get_network(network_id)
    assets = await repository.all_assets(network_id)
    links = await repository.all_links(network_id)
    controls = await control_repository.all_controls(network_id)
    codes_by_id = {asset.id: asset.code for asset in assets}
    return NetworkFile(
        network=NetworkCreate(name=network.name, description=network.description),
        assets=[AssetCreate.model_validate(asset.model_dump()) for asset in assets],
        links=[
            ImportLink(
                source=codes_by_id[link.source_asset_id],
                target=codes_by_id[link.target_asset_id],
                **link.model_dump(
                    include={"code", "type", "allowed_protocols", "allowed_ports", "bidirectional"}
                ),
            )
            for link in links
        ],
        controls=[
            ImportControl(
                placement=ImportPlacement(
                    kind=control.placement.kind,
                    asset_codes=[
                        codes_by_id[asset_id]
                        for asset_id in control.placement.asset_ids
                        if asset_id in codes_by_id
                    ],
                    zones=control.placement.zones,
                    services=control.placement.services,
                ),
                **control.model_dump(include={"code", "name", "type", "enabled", "config"}),
            )
            for control in controls
        ],
    )
