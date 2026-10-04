"""Digital twin API: networks, assets, links, import/export, graph and paths."""

from typing import Annotated, Any

from fastapi import APIRouter, File, Query, Response, UploadFile, status
from pydantic import ValidationError

from app.api.deps import NetworkDep, PaginationDep
from app.controls import repository as control_repository
from app.controls.placement import protecting_controls
from app.core.config import get_settings
from app.core.errors import Conflict, ValidationFailed
from app.models.asset import Asset, AssetCreate, AssetRead, AssetUpdate
from app.models.common import Page, utcnow
from app.models.enums import AssetType, Zone
from app.models.link import Link, LinkCreate, LinkRead, LinkUpdate
from app.models.network import Network, NetworkCreate, NetworkRead, NetworkUpdate
from app.models.twin_io import (
    GraphEdge,
    GraphNode,
    GraphResponse,
    ImportResult,
    NetworkFile,
    NodeControl,
    PathItem,
    PathsResponse,
    ZoneCrossing,
)
from app.twin import graph as twin_graph
from app.twin import layout, loader, repository
from app.twin.versioning import bump_version

router = APIRouter(tags=["twin"])


def _validation_details(exc: ValidationError) -> dict[str, Any]:
    """Convert a Pydantic error into the details block of the shared error format."""
    return {
        "errors": [
            {"loc": [str(part) for part in error["loc"]], "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
    }


async def _read_upload(file: UploadFile) -> bytes:
    """Read an uploaded file, rejecting files above the configured size."""
    limit = get_settings().max_import_bytes
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise ValidationFailed(f"Import file is larger than {limit} bytes", {"max_bytes": limit})
    return content


def _require_imported(result: ImportResult) -> ImportResult:
    """Raise ValidationFailed carrying every import error, or pass the result through."""
    if result.errors:
        raise ValidationFailed(
            f"Import rejected with {len(result.errors)} error(s). Nothing was written.",
            {"errors": result.errors},
        )
    return result


# --- networks ---------------------------------------------------------------


@router.post("/networks", response_model=NetworkRead, status_code=status.HTTP_201_CREATED)
async def create_network(payload: NetworkCreate) -> Network:
    """Create an empty network."""
    return await repository.insert_network(Network(**payload.model_dump()))


@router.get("/networks", response_model=Page[NetworkRead])
async def list_networks(page: PaginationDep) -> Page[Network]:
    """List networks."""
    items, total = await repository.list_networks(page.limit, page.offset)
    return Page[Network](items=items, total=total)


@router.post("/networks/import", response_model=ImportResult, status_code=status.HTTP_201_CREATED)
async def import_new_network(file: Annotated[UploadFile, File()]) -> ImportResult:
    """Create a new network from a JSON or YAML twin file."""
    content = await _read_upload(file)
    return _require_imported(await loader.import_network(content, file.filename or ""))


@router.get("/networks/{network_id}", response_model=NetworkRead)
async def get_network(network: NetworkDep) -> Network:
    """Return one network."""
    return network


@router.patch("/networks/{network_id}", response_model=NetworkRead)
async def update_network(network: NetworkDep, payload: NetworkUpdate) -> Network:
    """Rename or re-describe a network. Does not change its version."""
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return network
    return await repository.update_network(network.id, changes)


@router.delete("/networks/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_network(network: NetworkDep) -> Response:
    """Delete a network and all of its assets and links."""
    await repository.delete_network(network.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/networks/{network_id}/import",
    response_model=ImportResult,
    status_code=status.HTTP_201_CREATED,
)
async def import_into_network(
    network: NetworkDep, file: Annotated[UploadFile, File()]
) -> ImportResult:
    """Load a twin file into an existing empty network. 409 when it already has content."""
    content = await _read_upload(file)
    return _require_imported(
        await loader.import_network(content, file.filename or "", network_id=network.id)
    )


@router.get("/networks/{network_id}/export", response_model=NetworkFile)
async def export_network(network: NetworkDep) -> NetworkFile:
    """Export a network in the import file shape."""
    return await loader.export_network(network.id)


# --- assets -----------------------------------------------------------------


@router.post(
    "/networks/{network_id}/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED
)
async def create_asset(network: NetworkDep, payload: AssetCreate) -> Asset:
    """Add an asset to a network."""
    if payload.ip is not None and await repository.ip_in_use(network.id, payload.ip):
        raise Conflict(f"IP address {payload.ip} is already used in this network", {"ip": payload.ip})
    asset = await repository.insert_asset(Asset(network_id=network.id, **payload.model_dump()))
    await bump_version(network.id)
    return asset


@router.get("/networks/{network_id}/assets", response_model=Page[AssetRead])
async def list_assets(
    network: NetworkDep,
    page: PaginationDep,
    zone: Annotated[Zone | None, Query()] = None,
    asset_type: Annotated[AssetType | None, Query(alias="type")] = None,
) -> Page[Asset]:
    """List a network's assets, optionally filtered by zone and type."""
    items, total = await repository.list_assets(
        network.id, page.limit, page.offset, zone=zone, asset_type=asset_type
    )
    return Page[Asset](items=items, total=total)


@router.get("/networks/{network_id}/assets/{asset_id}", response_model=AssetRead)
async def get_asset(network: NetworkDep, asset_id: str) -> Asset:
    """Return one asset."""
    return await repository.get_asset(network.id, asset_id)


@router.patch("/networks/{network_id}/assets/{asset_id}", response_model=AssetRead)
async def update_asset(network: NetworkDep, asset_id: str, payload: AssetUpdate) -> Asset:
    """Change fields of an asset. Increments the network version."""
    current = await repository.get_asset(network.id, asset_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return current
    updated = Asset.model_validate({**current.model_dump(), **changes, "updated_at": utcnow()})
    if updated.ip is not None and await repository.ip_in_use(network.id, updated.ip, asset_id):
        raise Conflict(f"IP address {updated.ip} is already used in this network", {"ip": updated.ip})
    await repository.replace_asset(updated)
    await bump_version(network.id)
    return updated


@router.delete(
    "/networks/{network_id}/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_asset(network: NetworkDep, asset_id: str) -> Response:
    """Delete an asset and every link attached to it. Increments the network version."""
    await repository.delete_asset(network.id, asset_id)
    await bump_version(network.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- links ------------------------------------------------------------------


async def _require_link_endpoints(network_id: str, link: Link) -> None:
    """Raise ValidationFailed when a link endpoint is not an asset of the network."""
    known = {asset.id for asset in await repository.all_assets(network_id)}
    missing = [
        asset_id for asset_id in (link.source_asset_id, link.target_asset_id) if asset_id not in known
    ]
    if missing:
        raise ValidationFailed(
            "Link endpoints must be assets of this network", {"missing_asset_ids": missing}
        )


@router.post(
    "/networks/{network_id}/links", response_model=LinkRead, status_code=status.HTTP_201_CREATED
)
async def create_link(network: NetworkDep, payload: LinkCreate) -> Link:
    """Connect two assets of a network."""
    link = Link(network_id=network.id, **payload.model_dump())
    await _require_link_endpoints(network.id, link)
    await repository.insert_link(link)
    await bump_version(network.id)
    return link


@router.get("/networks/{network_id}/links", response_model=Page[LinkRead])
async def list_links(network: NetworkDep, page: PaginationDep) -> Page[Link]:
    """List a network's links."""
    items, total = await repository.list_links(network.id, page.limit, page.offset)
    return Page[Link](items=items, total=total)


@router.get("/networks/{network_id}/links/{link_id}", response_model=LinkRead)
async def get_link(network: NetworkDep, link_id: str) -> Link:
    """Return one link."""
    return await repository.get_link(network.id, link_id)


@router.patch("/networks/{network_id}/links/{link_id}", response_model=LinkRead)
async def update_link(network: NetworkDep, link_id: str, payload: LinkUpdate) -> Link:
    """Change fields of a link. Increments the network version."""
    current = await repository.get_link(network.id, link_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return current
    try:
        updated = Link.model_validate({**current.model_dump(), **changes, "updated_at": utcnow()})
    except ValidationError as exc:
        raise ValidationFailed("Link update is not valid", _validation_details(exc)) from exc
    await _require_link_endpoints(network.id, updated)
    await repository.replace_link(updated)
    await bump_version(network.id)
    return updated


@router.delete("/networks/{network_id}/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_link(network: NetworkDep, link_id: str) -> Response:
    """Delete a link. Increments the network version."""
    await repository.delete_link(network.id, link_id)
    await bump_version(network.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- graph ------------------------------------------------------------------


@router.get("/networks/{network_id}/graph", response_model=GraphResponse)
async def get_graph(network: NetworkDep) -> GraphResponse:
    """Return the network as React Flow nodes and edges with a deterministic layout.

    Each node lists the controls whose placement covers that asset.
    """
    assets = await repository.all_assets(network.id)
    links = await repository.all_links(network.id)
    positions = layout.compute_positions(assets)
    controls = await control_repository.all_controls(network.id)
    return GraphResponse(
        nodes=[
            GraphNode(
                id=asset.id,
                position=positions[asset.id],
                data=AssetRead(**asset.model_dump()),
                controls=[
                    NodeControl(
                        code=control.code,
                        name=control.name,
                        type=control.type,
                        kind=control.placement.kind,
                        enabled=control.enabled,
                    )
                    for control in protecting_controls(asset, controls)
                ],
            )
            for asset in assets
        ],
        edges=[
            GraphEdge(
                id=link.id,
                source=link.source_asset_id,
                target=link.target_asset_id,
                data=LinkRead(**link.model_dump()),
            )
            for link in links
        ],
        zones=layout.group_by_zone(assets),
    )


@router.get("/networks/{network_id}/paths", response_model=PathsResponse)
async def get_paths(
    network: NetworkDep,
    from_asset_id: Annotated[str, Query(alias="from", min_length=1)],
    to_asset_id: Annotated[str, Query(alias="to", min_length=1)],
    max_hops: Annotated[int, Query(ge=1, le=10)] = 6,
) -> PathsResponse:
    """Return simple paths between two assets, shortest first, with their zone crossings."""
    if from_asset_id == to_asset_id:
        raise ValidationFailed("'from' and 'to' must be different assets", {"asset_id": from_asset_id})
    graph = await twin_graph.build_graph(network.id)
    paths = twin_graph.all_paths(graph, from_asset_id, to_asset_id, max_hops=max_hops)
    return PathsResponse(
        paths=[
            PathItem(
                **path.model_dump(),
                zone_crossings=[
                    ZoneCrossing(from_zone=from_zone, to_zone=to_zone)
                    for from_zone, to_zone in twin_graph.zone_crossings(graph, path.asset_ids)
                ],
            )
            for path in paths
        ]
    )
