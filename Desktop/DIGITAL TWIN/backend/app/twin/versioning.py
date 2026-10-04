"""Network version counter. Bumped on every change to assets, links or controls."""

from pymongo import ReturnDocument

from app.core import db
from app.core.errors import NotFound
from app.models.common import utcnow


async def bump_version(network_id: str) -> int:
    """Increment a network's version, refresh updated_at and return the new version."""
    document = await db.collection(db.NETWORKS).find_one_and_update(
        {"id": network_id},
        {"$inc": {"version": 1}, "$set": {"updated_at": utcnow()}},
        projection={"_id": 0, "version": 1},
        return_document=ReturnDocument.AFTER,
    )
    if document is None:
        raise NotFound(f"Network {network_id} not found", {"network_id": network_id})
    return int(document["version"])
