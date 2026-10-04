"""Network posture: one score for the whole twin, from its scenario risks and coverage."""

from collections.abc import Sequence

from app.analysis import risk, service
from pymongo import ASCENDING

from app.controls.coverage import coverage
from app.core import db
from app.models.analysis import (
    Findings,
    Posture,
    PostureBreakdown,
    PostureSnapshot,
    ScenarioRisk,
    WeakestLinkCount,
)
from app.models.enums import FinalOutcome, RunStatus
from app.models.run import DEFAULT_SEED, SimulationRun
from app.scenarios import catalog as scenario_catalog
from app.simulation import engine
from app.simulation import repository as run_repository
from app.twin import repository as twin_repository

COVERAGE_FLOOR = 0.75
COVERAGE_SPAN = 0.25
TOP_RISKS = 3
FORMULA = (
    "posture_score = round((100 - average_risk) x coverage_factor); "
    "coverage_factor = coverage_floor + coverage_span x coverage_percent / 100"
)


def scenario_risk(run: SimulationRun, findings: Findings) -> ScenarioRisk:
    """Summarise one run as a scenario's risk."""
    scored = risk.score_run(findings)
    return ScenarioRisk(
        scenario_code=run.scenario_code,
        run_id=run.id,
        risk_score=scored.score,
        band=scored.band,
        containment=findings.containment,
        weakest_link=findings.weakest_link,
    )


def count_weakest_links(per_scenario: Sequence[ScenarioRisk]) -> list[WeakestLinkCount]:
    """Group scenarios by their weakest link, most shared first."""
    groups: dict[tuple[str, str], WeakestLinkCount] = {}
    for item in per_scenario:
        link = item.weakest_link
        if link is None:
            continue
        key = (link.kind.value, link.ref)
        if key not in groups:
            groups[key] = WeakestLinkCount(kind=link.kind, ref=link.ref, count=0, scenario_codes=[])
        groups[key].count += 1
        groups[key].scenario_codes.append(item.scenario_code)
    return sorted(groups.values(), key=lambda group: (-group.count, group.kind.value, group.ref))


def build_posture(
    network_id: str,
    network_version: int,
    per_scenario: Sequence[ScenarioRisk],
    coverage_percent: float,
    stale_scenarios: Sequence[str] = (),
) -> Posture:
    """Compute posture from scenario risks and coverage. Pure.

    posture_score = round((100 - average_risk) x (0.75 + 0.25 x coverage_percent / 100)).
    Full coverage deducts nothing; zero coverage removes a quarter of the score.
    With no scenario results the average risk is taken as 0.
    """
    ordered = sorted(per_scenario, key=lambda item: item.scenario_code)
    average = round(sum(item.risk_score for item in ordered) / len(ordered), 2) if ordered else 0.0
    base = round(100 - average, 2)
    factor = round(COVERAGE_FLOOR + COVERAGE_SPAN * coverage_percent / 100, 4)
    return Posture(
        network_id=network_id,
        network_version=network_version,
        posture_score=min(100, max(0, risk.round_half_up(base * factor))),
        per_scenario=ordered,
        average_risk=average,
        coverage_percent=coverage_percent,
        top_risks=sorted(ordered, key=lambda item: (-item.risk_score, item.scenario_code))[:TOP_RISKS],
        worst_weakest_links=count_weakest_links(ordered),
        stale_scenarios=sorted(stale_scenarios),
        breakdown=PostureBreakdown(
            average_risk=average,
            base_score=base,
            coverage_percent=coverage_percent,
            coverage_factor=factor,
            formula=FORMULA,
            constants={"coverage_floor": COVERAGE_FLOOR, "coverage_span": COVERAGE_SPAN},
        ),
    )


async def posture(network_id: str, refresh: bool = True) -> Posture:
    """Return the posture of a network on its current version.

    Uses the latest run of each scenario on the current network version. With
    `refresh`, a scenario that has no such run is simulated first with the default
    seed. Without it, that scenario is listed in `stale_scenarios` and left out of the
    average. A scenario whose latest current run failed is always listed as stale.
    """
    network = await twin_repository.get_network(network_id)
    per_scenario: list[ScenarioRisk] = []
    stale: list[str] = []
    for scenario in scenario_catalog.all():
        run = await run_repository.latest_run(network.id, scenario.id, network.version)
        if run is None and refresh:
            run = await engine.run(network.id, scenario.id, DEFAULT_SEED)
        if run is None or run.status != RunStatus.COMPLETED:
            stale.append(scenario.code)
            continue
        per_scenario.append(scenario_risk(run, await service.findings_for(run)))
    covered = await coverage(network.id)
    result = build_posture(network.id, network.version, per_scenario, covered.coverage_percent, stale)
    if not stale:
        await save_snapshot(result)
    return result


def to_snapshot(result: Posture) -> PostureSnapshot:
    """Reduce a posture to the values the trend line needs."""
    outcomes = [item.containment for item in result.per_scenario]
    return PostureSnapshot(
        network_id=result.network_id,
        network_version=result.network_version,
        posture_score=result.posture_score,
        average_risk=result.average_risk,
        coverage_percent=result.coverage_percent,
        scenarios_contained=outcomes.count(FinalOutcome.CONTAINED),
        scenarios_partially_contained=outcomes.count(FinalOutcome.PARTIALLY_CONTAINED),
        scenarios_reached=outcomes.count(FinalOutcome.OBJECTIVE_REACHED),
    )


async def save_snapshot(result: Posture) -> None:
    """Store the posture of a network version, replacing an earlier snapshot of that version."""
    snapshot = to_snapshot(result)
    document = snapshot.model_dump(mode="json")
    document["recorded_at"] = snapshot.recorded_at
    await db.collection(db.POSTURE_SNAPSHOTS).replace_one(
        {"network_id": snapshot.network_id, "network_version": snapshot.network_version},
        document,
        upsert=True,
    )


async def posture_history(network_id: str) -> list[PostureSnapshot]:
    """Return the stored posture snapshots of a network, oldest version first.

    A snapshot is stored each time a complete posture (no stale scenarios) is computed.
    Raises NotFound for unknown ids.
    """
    await twin_repository.get_network(network_id)
    cursor = db.collection(db.POSTURE_SNAPSHOTS).find({"network_id": network_id}, {"_id": 0})
    documents = await cursor.sort([("network_version", ASCENDING)]).to_list(length=None)
    return [PostureSnapshot.model_validate(document) for document in documents]
