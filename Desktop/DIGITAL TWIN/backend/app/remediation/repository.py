"""MongoDB reads and writes for remediations and the audit log."""

from collections.abc import Sequence
from typing import Any

from pymongo import ASCENDING

from app.core import db
from app.core.errors import NotFound
from app.models.common import utcnow
from app.models.enums import RemediationStatus
from app.models.remediation import AuditLog, Remediation

_NO_MONGO_ID: dict[str, int] = {"_id": 0}


async def insert_remediation(remediation: Remediation) -> Remediation:
    """Store a new remediation."""
    await db.collection(db.REMEDIATIONS).insert_one(remediation.to_document())
    return remediation


async def get_remediation(remediation_id: str) -> Remediation:
    """Return a remediation by id. Raises NotFound when it does not exist."""
    document = await db.collection(db.REMEDIATIONS).find_one({"id": remediation_id}, _NO_MONGO_ID)
    if document is None:
        raise NotFound(f"Remediation {remediation_id} not found", {"remediation_id": remediation_id})
    return Remediation.model_validate(document)


async def save_remediation(remediation: Remediation) -> Remediation:
    """Overwrite a stored remediation, refreshing updated_at."""
    updated = remediation.model_copy(update={"updated_at": utcnow()})
    result = await db.collection(db.REMEDIATIONS).replace_one({"id": updated.id}, updated.to_document())
    if result.matched_count == 0:
        raise NotFound(f"Remediation {updated.id} not found", {"remediation_id": updated.id})
    return updated


async def list_remediations(
    network_id: str, status: RemediationStatus | None = None
) -> list[Remediation]:
    """Return every remediation of a network, oldest first, optionally with one status."""
    query: dict[str, Any] = {"network_id": network_id}
    if status is not None:
        query["status"] = status.value
    cursor = db.collection(db.REMEDIATIONS).find(query, _NO_MONGO_ID)
    documents = await cursor.sort([("created_at", ASCENDING), ("id", ASCENDING)]).to_list(length=None)
    return [Remediation.model_validate(document) for document in documents]


async def find_open_by_fingerprint(
    network_id: str, fingerprint: str, statuses: Sequence[RemediationStatus]
) -> Remediation | None:
    """Return a remediation of the network with the same patch and one of the statuses."""
    document = await db.collection(db.REMEDIATIONS).find_one(
        {
            "network_id": network_id,
            "fingerprint": fingerprint,
            "status": {"$in": [status.value for status in statuses]},
        },
        _NO_MONGO_ID,
    )
    return Remediation.model_validate(document) if document is not None else None


async def insert_audit(entry: AuditLog) -> AuditLog:
    """Append an audit entry. Entries are never changed or removed."""
    await db.collection(db.AUDIT_LOG).insert_one(entry.to_document())
    return entry


async def list_audit(network_id: str, limit: int, offset: int) -> tuple[list[AuditLog], int]:
    """Return one page of a network's audit log, oldest first, and the total count."""
    query = {"network_id": network_id}
    entries = db.collection(db.AUDIT_LOG)
    total = await entries.count_documents(query)
    cursor = entries.find(query, _NO_MONGO_ID).sort([("at", ASCENDING), ("_id", ASCENDING)])
    documents = await cursor.skip(offset).limit(limit).to_list(length=limit)
    return [AuditLog.model_validate(document) for document in documents], total
