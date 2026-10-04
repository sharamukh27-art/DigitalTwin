"""All MongoDB reads and writes for networks, assets and links."""

from typing import Any

from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from app.controls import repository as control_repository
from app.core import db
from app.core.errors import Conflict, NotFound
from app.models.asset import Asset
from app.models.common import utcnow
from app.models.enums import AssetType, Zone
from app.models.link import Link
from app.models.network import Network

_NO_MONGO_ID: dict[str, int] = {"_id": 0}


# --- networks ---------------------------------------------------------------


async def insert_network(network: Network) -> Network:
    """Store a new network."""
    await db.collection(db.NETWORKS).insert_one(network.to_document())
    return network


async def get_network(network_id: str) -> Network:
    """Return a network by id. Raises NotFound when it does not exist."""
    document = await db.collection(db.NETWORKS).find_one({"id": network_id}, _NO_MONGO_ID)
    if document is None:
        raise NotFound(f"Network {network_id} not found", {"network_id": network_id})
    return Network.model_validate(document)


async def list_networks(limit: int, offset: int) -> tuple[list[Network], int]:
    """Return one page of networks, oldest first, and the total count."""
    networks = db.collection(db.NETWORKS)
    total = await networks.count_documents({})
    cursor = (
        networks.find({}, _NO_MONGO_ID)
        .sort([("created_at", ASCENDING), ("id", ASCENDING)])
        .skip(offset)
        .limit(limit)
    )
    documents = await cursor.to_list(length=limit)
    return [Network.model_validate(document) for document in documents], total


async def update_network(network_id: str, changes: dict[str, Any]) -> Network:
    """Apply field changes to a network and refresh its updated_at."""
    result = await db.collection(db.NETWORKS).update_one(
        {"id": network_id}, {"$set": {**changes, "updated_at": utcnow()}}
    )
    if result.matched_count == 0:
        raise NotFound(f"Network {network_id} not found", {"network_id": network_id})
    return await get_network(network_id)


async def delete_network(network_id: str) -> None:
    """Delete a network with everything stored for it.

    That is its assets, links, controls, runs, findings, explanations, remediations,
    audit log and posture snapshots.
    """
    await get_network(network_id)
    await delete_network_contents(network_id)
    await db.collection(db.SIMULATION_RUNS).delete_many({"network_id": network_id})
    await db.collection(db.FINDINGS).delete_many({"network_id": network_id})
    await db.collection(db.EXPLANATIONS).delete_many({"network_id": network_id})
    await db.collection(db.REMEDIATIONS).delete_many({"network_id": network_id})
    await db.collection(db.AUDIT_LOG).delete_many({"network_id": network_id})
    await db.collection(db.POSTURE_SNAPSHOTS).delete_many({"network_id": network_id})
    await db.collection(db.NETWORKS).delete_one({"id": network_id})


async def delete_network_contents(network_id: str) -> None:
    """Delete every asset, link and control of a network, leaving the network itself."""
    await control_repository.delete_controls_for_network(network_id)
    await db.collection(db.LINKS).delete_many({"network_id": network_id})
    await db.collection(db.ASSETS).delete_many({"network_id": network_id})


async def remove_network_document(network_id: str) -> None:
    """Delete only the network document. Used to roll back a failed import."""
    await db.collection(db.NETWORKS).delete_one({"id": network_id})


# --- assets -----------------------------------------------------------------


async def insert_asset(asset: Asset) -> Asset:
    """Store a new asset. Raises Conflict when its code is already used in the network."""
    try:
        await db.collection(db.ASSETS).insert_one(asset.to_document())
    except DuplicateKeyError as exc:
        raise Conflict(
            f"Asset code {asset.code} already exists in this network", {"code": asset.code}
        ) from exc
    return asset


async def insert_assets(assets: list[Asset]) -> None:
    """Store many assets at once."""
    if assets:
        await db.collection(db.ASSETS).insert_many([asset.to_document() for asset in assets])


async def get_asset(network_id: str, asset_id: str) -> Asset:
    """Return an asset of a network. Raises NotFound when it does not exist."""
    document = await db.collection(db.ASSETS).find_one(
        {"network_id": network_id, "id": asset_id}, _NO_MONGO_ID
    )
    if document is None:
        raise NotFound(
            f"Asset {asset_id} not found", {"network_id": network_id, "asset_id": asset_id}
        )
    return Asset.model_validate(document)


async def list_assets(
    network_id: str,
    limit: int,
    offset: int,
    zone: Zone | None = None,
    asset_type: AssetType | None = None,
) -> tuple[list[Asset], int]:
    """Return one page of a network's assets ordered by code, and the total count."""
    query: dict[str, Any] = {"network_id": network_id}
    if zone is not None:
        query["zone"] = zone.value
    if asset_type is not None:
        query["type"] = asset_type.value
    assets = db.collection(db.ASSETS)
    total = await assets.count_documents(query)
    cursor = assets.find(query, _NO_MONGO_ID).sort([("code", ASCENDING)]).skip(offset).limit(limit)
    documents = await cursor.to_list(length=limit)
    return [Asset.model_validate(document) for document in documents], total


async def all_assets(network_id: str) -> list[Asset]:
    """Return every asset of a network ordered by code."""
    cursor = db.collection(db.ASSETS).find({"network_id": network_id}, _NO_MONGO_ID)
    documents = await cursor.sort([("code", ASCENDING)]).to_list(length=None)
    return [Asset.model_validate(document) for document in documents]


async def count_assets(network_id: str) -> int:
    """Return how many assets a network has."""
    return await db.collection(db.ASSETS).count_documents({"network_id": network_id})


async def ip_in_use(network_id: str, ip: str, exclude_asset_id: str | None = None) -> bool:
    """Return True when another asset of the network already uses the IP address."""
    query: dict[str, Any] = {"network_id": network_id, "ip": ip}
    if exclude_asset_id is not None:
        query["id"] = {"$ne": exclude_asset_id}
    return await db.collection(db.ASSETS).count_documents(query) > 0


async def replace_asset(asset: Asset) -> Asset:
    """Overwrite a stored asset. Raises Conflict when its new code is already used."""
    try:
        result = await db.collection(db.ASSETS).replace_one(
            {"network_id": asset.network_id, "id": asset.id}, asset.to_document()
        )
    except DuplicateKeyError as exc:
        raise Conflict(
            f"Asset code {asset.code} already exists in this network", {"code": asset.code}
        ) from exc
    if result.matched_count == 0:
        raise NotFound(f"Asset {asset.id} not found", {"asset_id": asset.id})
    return asset


async def delete_asset(network_id: str, asset_id: str) -> int:
    """Delete an asset and every link attached to it. Returns the number of links removed.

    The asset is also dropped from the placement of any control that listed it.
    """
    await get_asset(network_id, asset_id)
    removed = await db.collection(db.LINKS).delete_many(
        {
            "network_id": network_id,
            "$or": [{"source_asset_id": asset_id}, {"target_asset_id": asset_id}],
        }
    )
    await control_repository.remove_asset_from_placements(network_id, asset_id)
    await db.collection(db.ASSETS).delete_one({"network_id": network_id, "id": asset_id})
    return int(removed.deleted_count)


# --- links ------------------------------------------------------------------


async def insert_link(link: Link) -> Link:
    """Store a new link. Raises Conflict when its code is already used in the network."""
    try:
        await db.collection(db.LINKS).insert_one(link.to_document())
    except DuplicateKeyError as exc:
        raise Conflict(
            f"Link code {link.code} already exists in this network", {"code": link.code}
        ) from exc
    return link


async def insert_links(links: list[Link]) -> None:
    """Store many links at once."""
    if links:
        await db.collection(db.LINKS).insert_many([link.to_document() for link in links])


async def get_link(network_id: str, link_id: str) -> Link:
    """Return a link of a network. Raises NotFound when it does not exist."""
    document = await db.collection(db.LINKS).find_one(
        {"network_id": network_id, "id": link_id}, _NO_MONGO_ID
    )
    if document is None:
        raise NotFound(f"Link {link_id} not found", {"network_id": network_id, "link_id": link_id})
    return Link.model_validate(document)


async def list_links(network_id: str, limit: int, offset: int) -> tuple[list[Link], int]:
    """Return one page of a network's links ordered by code, and the total count."""
    query = {"network_id": network_id}
    links = db.collection(db.LINKS)
    total = await links.count_documents(query)
    cursor = links.find(query, _NO_MONGO_ID).sort([("code", ASCENDING)]).skip(offset).limit(limit)
    documents = await cursor.to_list(length=limit)
    return [Link.model_validate(document) for document in documents], total


async def all_links(network_id: str) -> list[Link]:
    """Return every link of a network ordered by code."""
    cursor = db.collection(db.LINKS).find({"network_id": network_id}, _NO_MONGO_ID)
    documents = await cursor.sort([("code", ASCENDING)]).to_list(length=None)
    return [Link.model_validate(document) for document in documents]


async def count_links(network_id: str) -> int:
    """Return how many links a network has."""
    return await db.collection(db.LINKS).count_documents({"network_id": network_id})


async def replace_link(link: Link) -> Link:
    """Overwrite a stored link. Raises Conflict when its new code is already used."""
    try:
        result = await db.collection(db.LINKS).replace_one(
            {"network_id": link.network_id, "id": link.id}, link.to_document()
        )
    except DuplicateKeyError as exc:
        raise Conflict(
            f"Link code {link.code} already exists in this network", {"code": link.code}
        ) from exc
    if result.matched_count == 0:
        raise NotFound(f"Link {link.id} not found", {"link_id": link.id})
    return link


async def delete_link(network_id: str, link_id: str) -> None:
    """Delete a link. Raises NotFound when it does not exist."""
    await get_link(network_id, link_id)
    await db.collection(db.LINKS).delete_one({"network_id": network_id, "id": link_id})
