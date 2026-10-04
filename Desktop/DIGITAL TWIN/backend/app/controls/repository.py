"""All MongoDB reads and writes for security controls."""

from typing import Any

from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from app.core import db
from app.core.errors import Conflict, NotFound
from app.models.control import SecurityControl
from app.models.enums import ControlType

_NO_MONGO_ID: dict[str, int] = {"_id": 0}


def _conflict(control: SecurityControl) -> Conflict:
    return Conflict(
        f"Control code {control.code} already exists in this network", {"code": control.code}
    )


async def insert_control(control: SecurityControl) -> SecurityControl:
    """Store a new control. Raises Conflict when its code is already used in the network."""
    try:
        await db.collection(db.CONTROLS).insert_one(control.to_document())
    except DuplicateKeyError as exc:
        raise _conflict(control) from exc
    return control


async def insert_controls(controls: list[SecurityControl]) -> None:
    """Store many controls at once."""
    if controls:
        await db.collection(db.CONTROLS).insert_many(
            [control.to_document() for control in controls]
        )


async def get_control(network_id: str, control_id: str) -> SecurityControl:
    """Return a control of a network. Raises NotFound when it does not exist."""
    document = await db.collection(db.CONTROLS).find_one(
        {"network_id": network_id, "id": control_id}, _NO_MONGO_ID
    )
    if document is None:
        raise NotFound(
            f"Control {control_id} not found", {"network_id": network_id, "control_id": control_id}
        )
    return SecurityControl.model_validate(document)


async def list_controls(
    network_id: str, limit: int, offset: int, control_type: ControlType | None = None
) -> tuple[list[SecurityControl], int]:
    """Return one page of a network's controls ordered by code, and the total count."""
    query: dict[str, Any] = {"network_id": network_id}
    if control_type is not None:
        query["type"] = control_type.value
    controls = db.collection(db.CONTROLS)
    total = await controls.count_documents(query)
    cursor = (
        controls.find(query, _NO_MONGO_ID).sort([("code", ASCENDING)]).skip(offset).limit(limit)
    )
    documents = await cursor.to_list(length=limit)
    return [SecurityControl.model_validate(document) for document in documents], total


async def all_controls(network_id: str) -> list[SecurityControl]:
    """Return every control of a network ordered by code."""
    cursor = db.collection(db.CONTROLS).find({"network_id": network_id}, _NO_MONGO_ID)
    documents = await cursor.sort([("code", ASCENDING)]).to_list(length=None)
    return [SecurityControl.model_validate(document) for document in documents]


async def count_controls(network_id: str) -> int:
    """Return how many controls a network has."""
    return await db.collection(db.CONTROLS).count_documents({"network_id": network_id})


async def replace_control(control: SecurityControl) -> SecurityControl:
    """Overwrite a stored control. Raises Conflict when its new code is already used."""
    try:
        result = await db.collection(db.CONTROLS).replace_one(
            {"network_id": control.network_id, "id": control.id}, control.to_document()
        )
    except DuplicateKeyError as exc:
        raise _conflict(control) from exc
    if result.matched_count == 0:
        raise NotFound(f"Control {control.id} not found", {"control_id": control.id})
    return control


async def delete_control(network_id: str, control_id: str) -> None:
    """Delete a control. Raises NotFound when it does not exist."""
    await get_control(network_id, control_id)
    await db.collection(db.CONTROLS).delete_one({"network_id": network_id, "id": control_id})


async def delete_controls_for_network(network_id: str) -> None:
    """Delete every control of a network."""
    await db.collection(db.CONTROLS).delete_many({"network_id": network_id})


async def remove_asset_from_placements(network_id: str, asset_id: str) -> None:
    """Drop a deleted asset from the placement of every control that listed it."""
    await db.collection(db.CONTROLS).update_many(
        {"network_id": network_id, "placement.asset_ids": asset_id},
        {"$pull": {"placement.asset_ids": asset_id}},
    )
