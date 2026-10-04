"""Deterministic simulation engine: runs a scenario's attack chain over the twin.

Pure logic over twin data. Nothing here sends packets or contacts a real host.
The same network version, scenario and seed always give the same step results:
the only source of randomness is one random.Random(seed).
"""

import logging
import random
from collections.abc import Sequence
from dataclasses import dataclass, field

import networkx as nx

from app.controls import evaluator
from app.controls import repository as control_repository
from app.models.asset import Asset
from app.models.common import utcnow
from app.models.control import SecurityControl
from app.models.enums import AssetType, ControlOutcome, EffectKind, RunStatus, StepOutcome
from app.models.evaluation import ConnectivityResult, ControlResult, StepContext
from app.models.link import Link
from app.models.run import (
    DEFAULT_SEED,
    FirstDetection,
    SimulationOutcome,
    SimulationRun,
    StepConnectivity,
    StepResult,
)
from app.models.scenario import Scenario, ScenarioStep, parse_effect
from app.models.technique import Technique
from app.models.twin_io import GraphPath
from app.scenarios import catalog as scenario_catalog
from app.simulation import goals, timing
from app.simulation import repository as run_repository
from app.simulation.targeting import (
    EngineError,
    TargetNotFound,
    asset_by_code,
    nearest,
    resolve_entry,
    resolve_target,
)
from app.twin import graph as twin_graph
from app.twin import repository as twin_repository
from app.twin import techniques

logger = logging.getLogger(__name__)

MAX_HOPS = 8
_SEEN = (ControlOutcome.BLOCKED, ControlOutcome.DETECTED, ControlOutcome.LOGGED)


@dataclass
class _World:
    """The twin as the engine sees it. Read-only during a run."""

    assets: dict[str, Asset]
    links: dict[str, Link]
    controls: list[SecurityControl]
    graph: nx.MultiDiGraph
    control_codes: dict[str, str]


@dataclass
class _State:
    """What the attacker has and where they are."""

    position: str
    positions: list[str]
    path_codes: list[str]
    effects: list[str] = field(default_factory=list)
    effect_log: list[tuple[EffectKind, Asset]] = field(default_factory=list)


@dataclass
class _Attempt:
    """One candidate path tried for a step."""

    path: GraphPath
    connectivity: ConnectivityResult
    results: list[ControlResult]

    @property
    def stopped(self) -> bool:
        return not self.connectivity.allowed or any(
            result.outcome == ControlOutcome.BLOCKED for result in self.results
        )


def candidate_paths(
    graph: nx.MultiDiGraph, source: str, target: str, rng: random.Random
) -> list[GraphPath]:
    """Return paths from source to target, fewest hops first, ties shuffled by the seeded RNG."""
    if source == target:
        return [GraphPath(asset_ids=[source], link_ids=[], hops=0)]
    paths = twin_graph.all_paths(graph, source, target, max_hops=MAX_HOPS)
    ordered: list[GraphPath] = []
    for hops in sorted({path.hops for path in paths}):
        group = [path for path in paths if path.hops == hops]
        if len(group) > 1:
            rng.shuffle(group)
        ordered.extend(group)
    return ordered


def _attempt(world: _World, step: ScenarioStep, source: str, target: str, path: GraphPath) -> _Attempt:
    """Check connectivity and, if traffic is allowed, every control for one path."""
    context = StepContext(
        technique_id=step.technique_id,
        source_asset=world.assets[source],
        target_asset=world.assets[target],
        link=world.links[path.link_ids[0]] if path.hops == 1 else None,
        path_asset_ids=path.asset_ids,
        layer=step.layer,
        protocol=step.protocol,
        port=step.port,
        service=step.service,
    )
    connectivity = evaluator.check_connectivity(world.controls, context, skip_types=step.bypasses)
    if not connectivity.allowed:
        return _Attempt(path, connectivity, [])
    return _Attempt(path, connectivity, evaluator.evaluate_all(world.controls, context))


def _apply_success(
    world: _World, state: _State, step: ScenarioStep, target: str, path: GraphPath, rng: random.Random
) -> list[str]:
    """Move the attacker and apply the step's effects. Returns the effects applied."""
    if step.advance and target != state.position:
        state.path_codes.extend(world.assets[asset_id].code for asset_id in path.asset_ids[1:])
        state.position = target
        state.positions.append(target)

    applied: list[str] = []
    for effect in step.on_success:
        kind, argument = parse_effect(effect)
        if kind == EffectKind.MOVE_TO:
            destination = _move_destination(world, state.position, argument or "", rng)
            if destination != state.position:
                state.position = destination
                state.positions.append(destination)
                state.path_codes.append(world.assets[destination].code)
        else:
            if effect not in state.effects:
                state.effects.append(effect)
            state.effect_log.append((kind, world.assets[target]))
        applied.append(effect)
    return applied


def _move_destination(world: _World, position: str, argument: str, rng: random.Random) -> str:
    """Resolve the argument of move_to: an asset code, or an asset type (nearest of it)."""
    if any(asset.code == argument for asset in world.assets.values()):
        return asset_by_code(world.assets, argument).id
    if argument in {item.value for item in AssetType}:
        candidates = [asset.id for asset in world.assets.values() if asset.type.value == argument]
        destination = nearest(world.graph, position, candidates, world.assets, rng)
        if destination is not None:
            return destination
    raise EngineError(f"move_to:{argument} matches no asset in this network")


def _run_step(
    world: _World,
    scenario: Scenario,
    step: ScenarioStep,
    technique: Technique,
    state: _State,
    entry_id: str,
    offset: int,
    rng: random.Random,
) -> StepResult:
    """Run one step from the attacker's current position and return its result."""
    source = state.position
    source_code = world.assets[source].code

    def blocked(note: str, target_code: str | None = None) -> StepResult:
        return StepResult(
            step_order=step.order,
            technique_id=technique.id,
            technique_name=technique.name,
            tactic=technique.tactic,
            source_code=source_code,
            target_code=target_code,
            outcome=StepOutcome.BLOCKED,
            offset_seconds=offset,
            position_after=source_code,
            note=note,
        )

    held = set(scenario.initial_effects) | set(state.effects)
    unmet = [item for item in step.preconditions if item not in held]
    if unmet:
        return blocked(f"precondition {' and '.join(unmet)} not met")

    try:
        target = resolve_target(step, scenario.goal, world.graph, world.assets, source, entry_id, rng)
    except TargetNotFound as exc:
        return blocked(str(exc))
    target_code = world.assets[target].code

    paths = candidate_paths(world.graph, source, target, rng)
    if not paths:
        return blocked(f"no path from {source_code} to {target_code}", target_code)

    attempts: list[_Attempt] = []
    for path in paths:
        attempts.append(_attempt(world, step, source, target, path))
        if not attempts[-1].stopped:
            break
    final = attempts[-1]

    seen = [result for result in final.results if result.outcome in _SEEN]
    if final.stopped:
        outcome = StepOutcome.BLOCKED
        note = (
            f"traffic denied: {final.connectivity.reason}"
            if not final.connectivity.allowed
            else f"blocked by {seen[0].control_code}"
        )
        applied: list[str] = []
    else:
        outcome = StepOutcome.DETECTED_NOT_BLOCKED if seen else StepOutcome.UNDETECTED
        note = (
            f"detected by {', '.join(result.control_code for result in seen)}, not blocked"
            if seen
            else "no control saw this step"
        )
        applied = _apply_success(world, state, step, target, final.path, rng)
    if step.bypasses:
        skipped = " and ".join(item.value for item in step.bypasses)
        note += f". {skipped} not applied: {step.bypass_reason}"

    deciding = final.connectivity.deciding_control_id
    return StepResult(
        step_order=step.order,
        technique_id=technique.id,
        technique_name=technique.name,
        tactic=technique.tactic,
        source_code=source_code,
        target_code=target_code,
        link_code=world.links[final.path.link_ids[0]].code if final.path.hops == 1 else None,
        connectivity=StepConnectivity(
            allowed=final.connectivity.allowed,
            deciding_control_code=world.control_codes.get(deciding) if deciding else None,
            reason=final.connectivity.reason,
        ),
        control_results=final.results,
        outcome=outcome,
        chosen_path=[world.assets[asset_id].code for asset_id in final.path.asset_ids],
        alternatives_tried=len(attempts) - 1,
        offset_seconds=offset,
        effects_applied=applied,
        position_after=world.assets[state.position].code,
        note=note,
    )


def simulate(
    scenario: Scenario,
    assets: Sequence[Asset],
    links: Sequence[Link],
    controls: Sequence[SecurityControl],
    graph: nx.MultiDiGraph,
    seed: int,
) -> SimulationOutcome:
    """Run a scenario over twin data already in memory. Pure and deterministic.

    Per step: check preconditions, resolve the target, order candidate paths by hops
    (ties shuffled by the seeded RNG), then for each path check connectivity and every
    control. A path is stopped when traffic is denied or any control blocks. The step
    is blocked only when every path is stopped, and a blocked step ends the run.
    Otherwise the step is detected_not_blocked or undetected, its effects apply and
    the attacker advances.

    Raises EngineError when the scenario names an asset the network does not have.
    """
    rng = random.Random(seed)
    world = _World(
        assets={asset.id: asset for asset in assets},
        links={link.id: link for link in links},
        controls=list(controls),
        graph=graph,
        control_codes={control.id: control.code for control in controls},
    )
    entry = resolve_entry(scenario.entry, world.assets)
    state = _State(position=entry.id, positions=[entry.id], path_codes=[entry.code])

    results: list[StepResult] = []
    first_detection: FirstDetection | None = None
    offset = 0
    for step in scenario.steps:
        technique = techniques.get(step.technique_id)
        offset += timing.step_seconds(technique.tactic, rng)
        result = _run_step(world, scenario, step, technique, state, entry.id, offset, rng)
        results.append(result)
        seen = [item for item in result.control_results if item.outcome in _SEEN]
        if first_detection is None and seen:
            first_detection = FirstDetection(
                step_order=step.order, control_code=seen[0].control_code, offset_seconds=offset
            )
        if result.outcome == StepOutcome.BLOCKED:
            break

    positions = [world.assets[asset_id] for asset_id in state.positions]
    reached = goals.goal_reached(scenario.goal, positions, state.effect_log)
    landed = bool(state.effects) or len(state.positions) > 1
    return SimulationOutcome(
        step_results=results,
        final_outcome=goals.final_outcome(reached, landed),
        furthest_asset_code=positions[-1].code,
        deepest_zone=goals.deepest_zone(positions),
        path_taken=state.path_codes,
        effects_gained=state.effects,
        first_detection=first_detection,
    )


async def run(network_id: str, scenario_id: str, seed: int = DEFAULT_SEED) -> SimulationRun:
    """Run a scenario against a network and store the result.

    Raises NotFound for an unknown network or scenario. Any other error fails closed:
    the run is stored with status "failed", the error text and no step results.
    """
    network = await twin_repository.get_network(network_id)
    scenario = scenario_catalog.get(scenario_id)
    started_at = utcnow()
    identity = {
        "network_id": network.id,
        "network_version": network.version,
        "scenario_id": scenario.id,
        "scenario_code": scenario.code,
        "seed": seed,
        "started_at": started_at,
    }
    try:
        outcome = simulate(
            scenario,
            await twin_repository.all_assets(network_id),
            await twin_repository.all_links(network_id),
            await control_repository.all_controls(network_id),
            await twin_graph.build_graph(network_id),
            seed,
        )
        result = SimulationRun(
            **identity, status=RunStatus.COMPLETED, finished_at=utcnow(), **outcome.model_dump()
        )
    except Exception as exc:  # noqa: BLE001 - fail closed: record the error, keep no partial result
        logger.exception("simulation failed", extra={"network_id": network_id, "scenario": scenario.code})
        result = SimulationRun(
            **identity,
            status=RunStatus.FAILED,
            finished_at=utcnow(),
            error=f"{type(exc).__name__}: {exc}",
        )
    await run_repository.insert_run(result)
    return result
