"""MongoDB reads and writes for cached findings. One findings document per run."""

from pymongo.errors import DuplicateKeyError

from app.core import db
from app.models.analysis import Findings

_NO_MONGO_ID: dict[str, int] = {"_id": 0}


async def get_findings(run_id: str) -> Findings | None:
    """Return the cached findings of a run, or None when not computed yet."""
    document = await db.collection(db.FINDINGS).find_one({"run_id": run_id}, _NO_MONGO_ID)
    return Findings.model_validate(document) if document is not None else None


async def save_findings(findings: Findings) -> Findings:
    """Store findings. If another request stored them first, return those instead."""
    try:
        await db.collection(db.FINDINGS).insert_one(findings.to_document())
    except DuplicateKeyError:
        existing = await get_findings(findings.run_id)
        if existing is not None:
            return existing
        raise
    return findings
