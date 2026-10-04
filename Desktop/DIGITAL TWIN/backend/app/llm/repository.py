"""MongoDB reads and writes for cached explanations. One explanation per run."""

from app.core import db
from app.models.explanation import Explanation

_NO_MONGO_ID: dict[str, int] = {"_id": 0}


async def get_explanation(run_id: str) -> Explanation | None:
    """Return the stored explanation of a run, or None when none was generated."""
    document = await db.collection(db.EXPLANATIONS).find_one({"run_id": run_id}, _NO_MONGO_ID)
    return Explanation.model_validate(document) if document is not None else None


async def save_explanation(explanation: Explanation) -> Explanation:
    """Store an explanation, replacing any earlier one for the same run."""
    await db.collection(db.EXPLANATIONS).replace_one(
        {"run_id": explanation.run_id}, explanation.to_document(), upsert=True
    )
    return explanation
