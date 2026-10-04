"""Scenario and simulation API: scenario library, running simulations, reading runs."""

from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import NetworkDep, PaginationDep
from app.models.common import Page
from app.models.run import (
    RunEventsResponse,
    RunSummary,
    SimulateAllRequest,
    SimulateAllResponse,
    SimulateRequest,
    SimulationRun,
)
from app.models.scenario import Scenario
from app.scenarios import catalog as scenario_catalog
from app.simulation import engine, events
from app.simulation import repository as run_repository
from app.twin import repository as twin_repository

router = APIRouter(tags=["simulation"])


@router.get("/scenarios", response_model=Page[Scenario])
async def list_scenarios(page: PaginationDep) -> Page[Scenario]:
    """List the scenario library ordered by code."""
    scenarios = scenario_catalog.all()
    return Page[Scenario](
        items=scenarios[page.offset : page.offset + page.limit], total=len(scenarios)
    )


@router.get("/scenarios/{scenario_id}", response_model=Scenario)
async def get_scenario(scenario_id: str) -> Scenario:
    """Return one scenario by id or code."""
    return scenario_catalog.get(scenario_id)


@router.post(
    "/networks/{network_id}/simulate",
    response_model=SimulationRun,
    status_code=status.HTTP_201_CREATED,
)
async def simulate(network: NetworkDep, payload: SimulateRequest) -> SimulationRun:
    """Run one scenario against the network and store the run.

    A run whose engine fails is still stored and returned, with status "failed".
    """
    return await engine.run(network.id, payload.scenario_id, payload.seed)


@router.post(
    "/networks/{network_id}/simulate-all",
    response_model=SimulateAllResponse,
    status_code=status.HTTP_201_CREATED,
)
async def simulate_all(
    network: NetworkDep, payload: SimulateAllRequest | None = None
) -> SimulateAllResponse:
    """Run every scenario of the library against the network with one seed."""
    seed = (payload or SimulateAllRequest()).seed
    runs = [await engine.run(network.id, scenario.id, seed) for scenario in scenario_catalog.all()]
    current = await twin_repository.get_network(network.id)
    return SimulateAllResponse(
        network_id=network.id,
        network_version=current.version,
        seed=seed,
        runs=[RunSummary.from_run(item) for item in runs],
    )


@router.get("/networks/{network_id}/runs", response_model=Page[RunSummary])
async def list_runs(
    network: NetworkDep,
    page: PaginationDep,
    scenario_id: Annotated[str | None, Query(description="Scenario id or code")] = None,
) -> Page[RunSummary]:
    """List a network's runs, newest first, optionally for one scenario."""
    resolved = scenario_catalog.get(scenario_id).id if scenario_id is not None else None
    runs, total = await run_repository.list_runs(
        network.id, page.limit, page.offset, scenario_id=resolved
    )
    return Page[RunSummary](items=[RunSummary.from_run(item) for item in runs], total=total)


@router.get("/runs/{run_id}", response_model=SimulationRun)
async def get_run(run_id: str) -> SimulationRun:
    """Return one stored run in full."""
    return await run_repository.get_run(run_id)


@router.get("/runs/{run_id}/events", response_model=RunEventsResponse)
async def get_run_events(run_id: str) -> RunEventsResponse:
    """Return the ordered replay stream of a run: start, one event per step, end."""
    stored = await run_repository.get_run(run_id)
    return RunEventsResponse(
        run_id=stored.id,
        scenario_code=stored.scenario_code,
        status=stored.status,
        events=events.build_events(stored),
    )
