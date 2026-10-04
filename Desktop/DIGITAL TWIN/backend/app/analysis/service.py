"""Get-or-compute access to findings and risk for stored runs."""

from app.analysis import metrics, risk
from app.analysis import repository as findings_repository
from app.controls import repository as control_repository
from app.core.errors import ValidationFailed
from app.models.analysis import Findings, RiskScore, TwinSnapshot
from app.models.enums import RunStatus
from app.models.run import SimulationRun
from app.simulation import repository as run_repository
from app.twin import repository as twin_repository


async def load_twin(network_id: str) -> TwinSnapshot:
    """Load a network with its assets and controls. Raises NotFound for unknown ids."""
    return TwinSnapshot(
        network=await twin_repository.get_network(network_id),
        assets=await twin_repository.all_assets(network_id),
        controls=await control_repository.all_controls(network_id),
    )


async def findings_for(run: SimulationRun) -> Findings:
    """Return the findings of a run, computing and caching them on first use.

    Raises ValidationFailed for a run that did not complete.
    """
    if run.status != RunStatus.COMPLETED:
        raise ValidationFailed(
            f"Run {run.id} has status {run.status.value} and has no findings",
            {"run_id": run.id, "error": run.error},
        )
    cached = await findings_repository.get_findings(run.id)
    if cached is not None:
        return cached
    twin = await load_twin(run.network_id)
    return await findings_repository.save_findings(metrics.compute_findings(run, twin))


async def findings_for_run(run_id: str) -> Findings:
    """Return the findings of a run by id. Raises NotFound for unknown runs."""
    return await findings_for(await run_repository.get_run(run_id))


async def risk_for_run(run_id: str) -> RiskScore:
    """Return the risk score of a run by id."""
    return risk.score_run(await findings_for_run(run_id))
