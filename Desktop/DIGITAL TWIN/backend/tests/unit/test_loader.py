"""Import validation, atomicity and export round trip."""

import json
from typing import Any

import pytest
import yaml

from app.controls import repository as control_repository
from app.core import db
from app.core.errors import Conflict, NotFound
from app.models.network import Network
from app.twin import loader, repository


def as_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data).encode("utf-8")


def small_file() -> dict[str, Any]:
    """A minimal valid twin file with two assets and one link."""
    return {
        "network": {"name": "Small", "description": "two hosts"},
        "assets": [
            {"code": "A", "name": "Host A", "type": "server", "zone": "server", "ip": "10.0.0.1"},
            {"code": "B", "name": "Host B", "type": "server", "zone": "server", "ip": "10.0.0.2"},
        ],
        "links": [{"code": "L-1", "source": "A", "target": "B", "type": "ethernet"}],
    }


async def document_counts() -> tuple[int, int, int]:
    assert await db.collection(db.CONTROLS).count_documents({}) == 0
    return (
        await db.collection(db.NETWORKS).count_documents({}),
        await db.collection(db.ASSETS).count_documents({}),
        await db.collection(db.LINKS).count_documents({}),
    )


async def test_import_acme_has_no_errors(database: Any, acme_bytes: bytes) -> None:
    result = await loader.import_network(acme_bytes, "acme_corp.json")
    assert result.errors == []
    assert result.assets_created == 25
    assert result.links_created == 24
    assert result.controls_created == 14
    assert result.network_id is not None
    assert (await repository.get_network(result.network_id)).version == 1


async def test_link_codes_are_mapped_to_new_asset_ids(database: Any) -> None:
    result = await loader.import_network(as_json(small_file()), "small.json")
    assert result.network_id is not None
    ids = {asset.code: asset.id for asset in await repository.all_assets(result.network_id)}
    (link,) = await repository.all_links(result.network_id)
    assert (link.source_asset_id, link.target_asset_id) == (ids["A"], ids["B"])


async def test_yaml_import(database: Any) -> None:
    content = yaml.safe_dump(small_file()).encode("utf-8")
    result = await loader.import_network(content, "small.yaml")
    assert result.errors == []
    assert (result.assets_created, result.links_created) == (2, 1)


async def test_collects_every_error_and_writes_nothing(database: Any) -> None:
    data = small_file()
    data["assets"][0]["mac"] = "not-a-mac"
    data["assets"][0]["criticality"] = 6
    data["assets"][1]["ip"] = "999.1.1.1"
    data["assets"][1]["known_cves"] = [{"id": "CVE-1", "cvss": 5.0, "description": "bad id"}]
    data["assets"].append({"code": "A", "name": "Dup", "type": "server", "zone": "server"})
    data["assets"].append(
        {"code": "C", "name": "Same IP 1", "type": "server", "zone": "server", "ip": "10.0.0.9"}
    )
    data["assets"].append(
        {"code": "D", "name": "Same IP 2", "type": "server", "zone": "server", "ip": "10.0.0.9"}
    )
    data["links"].append({"code": "L-2", "source": "A", "target": "GHOST", "type": "ethernet"})
    data["links"].append({"code": "L-3", "source": "B", "target": "B", "type": "ethernet"})
    data["links"].append({"code": "L-3", "source": "A", "target": "B", "type": "ethernet"})

    result = await loader.import_network(as_json(data), "broken.json")

    assert result.network_id is None
    assert (result.assets_created, result.links_created) == (0, 0)
    joined = "\n".join(result.errors)
    for expected in (
        "MAC address",
        "criticality",
        "IPv4",
        "CVE id",
        "duplicate asset code 'A'",
        "duplicate IP address '10.0.0.9'",
        "duplicate link code 'L-3'",
        "missing asset code 'GHOST'",
        "self-link",
    ):
        assert expected in joined, f"missing error about: {expected}"
    assert len(result.errors) == 9
    assert await document_counts() == (0, 0, 0)


async def test_three_different_errors_are_all_returned(database: Any) -> None:
    data = small_file()
    data["assets"][0]["mac"] = "ZZ:ZZ"
    data["assets"][1]["code"] = "A"
    data["links"][0]["target"] = "NOPE"

    result = await loader.import_network(as_json(data), "three.json")

    assert len(result.errors) == 3
    assert await document_counts() == (0, 0, 0)


@pytest.mark.parametrize(
    ("content", "filename", "expected"),
    [
        (b"{}", "twin.txt", "unsupported file type"),
        (b"{not json", "twin.json", "could not be parsed"),
        (b"[1, 2]", "twin.json", "top level must be an object"),
        (b'{"assets": []}', "twin.json", "'network' section is required"),
        (b'{"network": {"name": "n"}, "assets": {}}', "twin.json", "'assets' must be a list"),
        (b"\xff\xfe", "twin.json", "not valid UTF-8"),
    ],
)
async def test_malformed_files_are_rejected(
    database: Any, content: bytes, filename: str, expected: str
) -> None:
    result = await loader.import_network(content, filename)
    assert len(result.errors) == 1
    assert expected in result.errors[0]
    assert await document_counts() == (0, 0, 0)


async def test_write_failure_is_rolled_back(database: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(_: Any) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(repository, "insert_links", fail)
    with pytest.raises(RuntimeError, match="disk full"):
        await loader.import_network(as_json(small_file()), "small.json")
    assert await document_counts() == (0, 0, 0)


async def test_import_into_existing_empty_network_bumps_version(database: Any) -> None:
    network = await repository.insert_network(Network(name="Target"))
    result = await loader.import_network(as_json(small_file()), "small.json", network_id=network.id)
    assert result.network_id == network.id
    stored = await repository.get_network(network.id)
    assert stored.name == "Target"
    assert stored.version == 2
    assert await document_counts() == (1, 2, 1)


async def test_failed_import_into_existing_network_keeps_the_network(
    database: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    network = await repository.insert_network(Network(name="Target"))

    async def fail(_: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(repository, "insert_links", fail)
    with pytest.raises(RuntimeError):
        await loader.import_network(as_json(small_file()), "small.json", network_id=network.id)
    assert await document_counts() == (1, 0, 0)
    assert (await repository.get_network(network.id)).version == 1


async def test_import_into_non_empty_network_is_a_conflict(database: Any, acme_id: str) -> None:
    with pytest.raises(Conflict):
        await loader.import_network(as_json(small_file()), "small.json", network_id=acme_id)


async def test_import_into_unknown_network_raises_not_found(database: Any) -> None:
    with pytest.raises(NotFound):
        await loader.import_network(as_json(small_file()), "small.json", network_id="missing")


async def test_export_unknown_network_raises_not_found(database: Any) -> None:
    with pytest.raises(NotFound):
        await loader.export_network("missing")


async def test_round_trip_export_import_is_identical(database: Any, acme_id: str) -> None:
    first = await loader.export_network(acme_id)
    content = first.model_dump_json().encode("utf-8")

    result = await loader.import_network(content, "export.json")
    assert result.errors == []
    assert result.network_id is not None and result.network_id != acme_id

    second = await loader.export_network(result.network_id)
    assert second.model_dump(mode="json") == first.model_dump(mode="json")


async def test_export_keeps_everything_from_the_source_file(
    database: Any, acme_id: str, acme_data: dict[str, Any]
) -> None:
    exported = (await loader.export_network(acme_id)).model_dump(mode="json")
    assert exported["network"] == acme_data["network"]
    assert exported["assets"] == sorted(acme_data["assets"], key=lambda item: item["code"])
    assert exported["links"] == sorted(acme_data["links"], key=lambda item: item["code"])
    assert exported["controls"] == sorted(acme_data["controls"], key=lambda item: item["code"])


def with_control(**overrides: Any) -> dict[str, Any]:
    """A small file with one EDR control on host A, changed by overrides."""
    data = small_file()
    control: dict[str, Any] = {
        "code": "EDR",
        "name": "Endpoint agent",
        "type": "edr",
        "placement": {"kind": "host", "asset_codes": ["A"]},
        "config": {"mode": "block"},
    }
    control.update(overrides)
    data["controls"] = [control]
    return data


async def test_control_placement_codes_are_mapped_to_asset_ids(database: Any) -> None:
    result = await loader.import_network(as_json(with_control()), "small.json")
    assert result.errors == []
    assert result.controls_created == 1
    assert result.network_id is not None
    ids = {asset.code: asset.id for asset in await repository.all_assets(result.network_id)}
    (control,) = await control_repository.all_controls(result.network_id)
    assert control.placement.asset_ids == [ids["A"]]
    assert control.network_id == result.network_id


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"config": {"mode": "sometimes"}}, "config.mode"),
        ({"config": {"mode": "block", "extra": 1}}, "config.extra"),
        ({"type": "antivirus"}, "type must be one of"),
        ({"placement": {"kind": "host", "asset_codes": ["GHOST"]}}, "missing asset code 'GHOST'"),
        ({"placement": {"kind": "host"}}, "host placement needs at least one asset"),
        ({"placement": {"kind": "sensor"}}, "sensor placement needs at least one zone"),
        ({"placement": {"kind": "identity"}}, "identity placement needs at least one service"),
    ],
)
async def test_bad_controls_are_rejected_and_nothing_is_written(
    database: Any, overrides: dict[str, Any], expected: str
) -> None:
    result = await loader.import_network(as_json(with_control(**overrides)), "small.json")
    assert len(result.errors) == 1
    assert expected in result.errors[0]
    assert await document_counts() == (0, 0, 0)


async def test_duplicate_control_codes_are_rejected(database: Any) -> None:
    data = with_control()
    data["controls"].append(dict(data["controls"][0]))
    result = await loader.import_network(as_json(data), "small.json")
    assert result.errors == ["duplicate control code 'EDR'"]


async def test_control_write_failure_is_rolled_back(
    database: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fail(_: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(control_repository, "insert_controls", fail)
    with pytest.raises(RuntimeError):
        await loader.import_network(as_json(with_control()), "small.json")
    assert await document_counts() == (0, 0, 0)


async def test_import_into_network_that_only_has_controls_is_a_conflict(database: Any) -> None:
    first = await loader.import_network(as_json(with_control()), "small.json")
    assert first.network_id is not None
    for asset in await repository.all_assets(first.network_id):
        await repository.delete_asset(first.network_id, asset.id)
    assert await repository.count_assets(first.network_id) == 0
    assert await control_repository.count_controls(first.network_id) == 1
    with pytest.raises(Conflict):
        await loader.import_network(as_json(small_file()), "small.json", network_id=first.network_id)
