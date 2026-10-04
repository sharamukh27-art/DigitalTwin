"""MongoDB reads and writes for simulation runs. Runs are immutable: insert and read only."""

from typing import Any

from pymongo import ASCENDING, DESCENDING

from app.core import db
from app.core.errors import NotFound
from app.models.run import SimulationRun

_NO_MONGO_ID: dict[str, int] = {"_id": 0}


async def insert_run(run: SimulationRun) -> SimulationRun:
    """Store a finished run."""
    await db.collection(db.SIMULATION_RUNS).insert_one(run.to_document())
    return run


async def get_run(run_id: str) -> SimulationRun:
    """Return a run by id. Raises NotFound when it does not exist."""
    document = await db.collection(db.SIMULATION_RUNS).find_one({"id": run_id}, _NO_MONGO_ID)
    if document is None:
        raise NotFound(f"Run {run_id} not found", {"run_id": run_id})
    return SimulationRun.model_validate(document)


async def latest_run(network_id: str, scenario_id: str, network_version: int) -> SimulationRun | None:
    """Return the newest run of a scenario on one network version, or None."""
    cursor = (
        db.collection(db.SIMULATION_RUNS)
        .find(
            {"network_id": network_id, "scenario_id": scenario_id, "network_version": network_version},
            _NO_MONGO_ID,
        )
        .sort([("created_at", DESCENDING), ("id", ASCENDING)])
        .limit(1)
    )
    documents = await cursor.to_list(length=1)
    return SimulationRun.model_validate(documents[0]) if documents else None


async def list_runs(
    network_id: str, limit: int, offset: int, scenario_id: str | None = None
) -> tuple[list[SimulationRun], int]:
    """Return one page of a network's runs, newest first, and the total count."""
    query: dict[str, Any] = {"network_id": network_id}
    if scenario_id is not None:
        query["scenario_id"] = scenario_id
    runs = db.collection(db.SIMULATION_RUNS)
    total = await runs.count_documents(query)
    cursor = (
        runs.find(query, _NO_MONGO_ID)
        .sort([("created_at", DESCENDING), ("scenario_code", ASCENDING), ("id", ASCENDING)])
        .skip(offset)
        .limit(limit)
    )
    documents = await cursor.to_list(length=limit)
    return [SimulationRun.model_validate(document) for document in documents], total
