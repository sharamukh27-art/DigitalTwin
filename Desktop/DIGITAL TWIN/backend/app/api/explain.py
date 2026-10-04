"""Explanation API: grounded explanations of runs and knowledge base status."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Query

from app.core.errors import NotFound
from app.llm import explain
from app.llm import repository as explanation_repository
from app.models.explanation import Explanation
from app.rag.documents import KbStatus
from app.rag.store import KnowledgeStore

router = APIRouter(tags=["explain"])


@router.post("/runs/{run_id}/explain", response_model=Explanation)
async def explain_run(
    run_id: str,
    force: Annotated[bool, Query(description="Regenerate even if an explanation is stored")] = False,
) -> Explanation:
    """Generate the explanation of a run and cache it. Returns the cached one if present."""
    return await explain.explain_run(run_id, force=force)


@router.get("/runs/{run_id}/explanation", response_model=Explanation)
async def get_explanation(run_id: str) -> Explanation:
    """Return the stored explanation of a run. 404 when none has been generated."""
    stored = await explanation_repository.get_explanation(run_id)
    if stored is None:
        raise NotFound(f"No explanation has been generated for run {run_id}", {"run_id": run_id})
    return stored


@router.get("/kb/status", response_model=KbStatus)
async def kb_status() -> KbStatus:
    """Return chunk counts per source, the embedding model and the last ingest time."""
    return await asyncio.to_thread(KnowledgeStore().status)
