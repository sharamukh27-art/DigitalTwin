"""Analysis API: findings, risk, posture, what-if and sandboxes."""

from typing import Annotated

from fastapi import APIRouter, Query, status

from app.analysis import attack_graph as attack_graph_module
from app.analysis import posture as posture_module
from app.analysis import service, whatif
from app.api.deps import NetworkDep
from app.models.analysis import Findings, Posture, PostureSnapshot, RiskScore
from app.models.attack_graph import AttackGraphResponse
from app.models.common import Page
from app.models.network import Network, NetworkRead
from app.models.whatif import WhatIfRequest, WhatIfResult

router = APIRouter(tags=["analysis"])


@router.get("/runs/{run_id}/findings", response_model=Findings)
async def get_findings(run_id: str) -> Findings:
    """Return the findings of a run. Computed on first request, then cached."""
    return await service.findings_for_run(run_id)


@router.get("/runs/{run_id}/risk", response_model=RiskScore)
async def get_risk(run_id: str) -> RiskScore:
    """Return the risk score of a run with its full breakdown."""
    return await service.risk_for_run(run_id)


@router.get("/networks/{network_id}/posture", response_model=Posture)
async def get_posture(
    network: NetworkDep,
    refresh: Annotated[
        bool, Query(description="Simulate scenarios that have no run on the current version")
    ] = True,
) -> Posture:
    """Return the posture of a network on its current version."""
    return await posture_module.posture(network.id, refresh=refresh)


@router.get("/networks/{network_id}/posture/history", response_model=Page[PostureSnapshot])
async def get_posture_history(network: NetworkDep) -> Page[PostureSnapshot]:
    """Return the posture recorded at each network version, oldest first, for a trend line."""
    items = await posture_module.posture_history(network.id)
    return Page[PostureSnapshot](items=items, total=len(items))


@router.get("/networks/{network_id}/attack-graph", response_model=AttackGraphResponse)
async def get_attack_graph(
    network: NetworkDep,
    min_criticality: Annotated[int, Query(ge=1, le=5, description="Lowest criticality that counts as a target")] = 4,
    max_hops: Annotated[int, Query(ge=1, le=6, description="Longest pivot chain to consider")] = 4,
) -> AttackGraphResponse:
    """Return pivot paths from the internet and guest zones to critical assets, and their choke points."""
    return await attack_graph_module.attack_graph(network.id, min_criticality, max_hops)


@router.post("/networks/{network_id}/whatif", response_model=WhatIfResult)
async def run_whatif(
    network: NetworkDep,
    payload: WhatIfRequest,
    keep: Annotated[bool, Query(description="Keep the sandbox instead of deleting it")] = False,
) -> WhatIfResult:
    """Compare the network before and after a patch, on a sandbox copy.

    The network itself is not changed and gets no runs.
    """
    return await whatif.whatif(
        network.id, payload.patch, scenario_ids=payload.scenario_ids, seed=payload.seed, keep=keep
    )


@router.post(
    "/networks/{network_id}/sandbox", response_model=NetworkRead, status_code=status.HTTP_201_CREATED
)
async def create_sandbox(network: NetworkDep) -> Network:
    """Clone the network into a sandbox. Delete it with DELETE /networks/{sandbox_id}."""
    return await whatif.clone_to_sandbox(network.id)
