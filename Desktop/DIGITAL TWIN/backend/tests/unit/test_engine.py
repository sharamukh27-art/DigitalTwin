"""Engine mechanics on small hand-built twins."""

import random
from typing import Any

import pytest

from app.core.errors import NotFound
from app.models.enums import FinalOutcome, RunStatus, StepOutcome
from app.models.network import Network
from app.simulation import engine, timing
from app.simulation import repository as run_repository
from app.simulation.targeting import EngineError
from app.twin import repository
from tests.sim import World, make_asset, make_link, make_scenario, make_world, step
from tests.steps import make_control

DENY_ALL = {"rules": [], "default_action": "deny", "logging": False}


def two_route_world(*controls: Any) -> World:
    """A -> B by a short route through F, or a longer one through R1 and R2."""
    assets = [
        make_asset("A", "workstation", "corporate"),
        make_asset("F", "firewall", "corporate"),
        make_asset("R1", "router", "corporate"),
        make_asset("R2", "router", "corporate"),
        make_asset("B", "server", "server", criticality=5),
    ]
    links = [
        make_link("L1", "A", "F"), make_link("L2", "F", "B"),
        make_link("L3", "A", "R1"), make_link("L4", "R1", "R2"), make_link("L5", "R2", "B"),
    ]
    world = make_world(assets, links)
    world.controls = [build(world) for build in controls]
    return world


def firewall_on(code: str, *asset_codes: str) -> Any:
    return lambda world: make_control(code, "firewall", "inline", DENY_ALL, assets=[world.asset(item) for item in asset_codes])


ONE_STEP = make_scenario([step(1, target_code="B", port=80, on_success=["gain_foothold"])])


def test_denied_path_falls_back_to_an_alternative() -> None:
    result = two_route_world(firewall_on("FW", "F")).run(ONE_STEP)
    only = result.step_results[0]
    assert only.chosen_path == ["A", "R1", "R2", "B"]
    assert only.alternatives_tried == 1
    assert only.connectivity is not None and only.connectivity.allowed is True
    assert only.outcome == StepOutcome.UNDETECTED
    assert only.link_code is None
    assert result.final_outcome == FinalOutcome.OBJECTIVE_REACHED
    assert result.path_taken == ["A", "R1", "R2", "B"]


def test_shortest_path_is_used_when_nothing_stops_it() -> None:
    only = two_route_world().run(ONE_STEP).step_results[0]
    assert (only.chosen_path, only.alternatives_tried) == (["A", "F", "B"], 0)


def test_step_is_blocked_when_every_path_is_denied() -> None:
    result = two_route_world(firewall_on("FW", "F"), firewall_on("FW2", "R1")).run(ONE_STEP)
    only = result.step_results[0]
    assert only.outcome == StepOutcome.BLOCKED
    assert only.alternatives_tried == 1
    assert only.connectivity is not None
    assert (only.connectivity.allowed, only.connectivity.deciding_control_code) == (False, "FW2")
    assert only.note.startswith("traffic denied: FW2 has no rule")
    assert only.control_results == []
    assert only.effects_applied == []
    assert (only.position_after, result.furthest_asset_code) == ("A", "A")
    assert result.final_outcome == FinalOutcome.CONTAINED
    assert result.first_detection is None


def test_control_block_also_falls_back_to_an_alternative() -> None:
    waf = lambda world: make_control("WAF", "waf", "inline", {"mode": "block", "rulesets": []}, assets=[world.asset("F")])  # noqa: E731
    result = two_route_world(waf).run(ONE_STEP)
    only = result.step_results[0]
    assert only.chosen_path == ["A", "R1", "R2", "B"]
    assert only.alternatives_tried == 1
    assert only.outcome == StepOutcome.UNDETECTED
    assert result.first_detection is None


def test_block_on_the_target_stops_every_path() -> None:
    waf = lambda world: make_control("WAF", "waf", "inline", {"mode": "block", "rulesets": []}, assets=[world.asset("B")])  # noqa: E731
    result = two_route_world(waf).run(ONE_STEP)
    only = result.step_results[0]
    assert (only.outcome, only.note, only.alternatives_tried) == (StepOutcome.BLOCKED, "blocked by WAF", 1)
    assert result.first_detection is not None
    assert (result.first_detection.step_order, result.first_detection.control_code) == (1, "WAF")
    assert result.first_detection.offset_seconds == only.offset_seconds


def test_bypass_skips_the_firewall_but_not_the_controls() -> None:
    scenario = make_scenario(
        [step(1, target_code="B", port=80, bypasses=["firewall"], bypass_reason="out of band")]
    )
    waf = lambda world: make_control("WAF", "waf", "inline", {"mode": "detect", "rulesets": []}, assets=[world.asset("B")])  # noqa: E731
    only = two_route_world(firewall_on("FW", "F", "R1"), waf).run(scenario).step_results[0]
    assert only.chosen_path == ["A", "F", "B"]
    assert only.outcome == StepOutcome.DETECTED_NOT_BLOCKED
    assert only.note == "detected by WAF, not blocked. firewall not applied: out of band"


def test_unmet_precondition_blocks_the_step_and_ends_the_run() -> None:
    scenario = make_scenario(
        [
            step(1, target_code="B", port=80, preconditions=["obtain_credentials", "escalate_privilege"]),
            step(2, target_selector="current_position"),
        ]
    )
    result = two_route_world().run(scenario)
    assert len(result.step_results) == 1
    only = result.step_results[0]
    assert only.outcome == StepOutcome.BLOCKED
    assert only.note == "precondition obtain_credentials and escalate_privilege not met"
    assert only.target_code is None and only.connectivity is None
    assert result.final_outcome == FinalOutcome.CONTAINED


def test_initial_effects_satisfy_preconditions() -> None:
    scenario = make_scenario(
        [step(1, target_code="B", port=80, preconditions=["obtain_credentials"])],
        initial_effects=["obtain_credentials"],
    )
    result = two_route_world().run(scenario)
    assert result.final_outcome == FinalOutcome.OBJECTIVE_REACHED
    assert result.effects_gained == []


def test_advance_false_keeps_the_attacker_in_place() -> None:
    scenario = make_scenario(
        [step(1, target_code="B", port=80, advance=False, on_success=["read_data"])],
        goal={"kind": "reach_asset", "target_code": "B"},
    )
    result = two_route_world().run(scenario)
    only = result.step_results[0]
    assert (only.position_after, result.furthest_asset_code, result.path_taken) == ("A", "A", ["A"])
    assert only.effects_applied == ["read_data"]
    assert result.final_outcome == FinalOutcome.PARTIALLY_CONTAINED


def test_move_to_effect_relocates_by_code_and_by_role() -> None:
    by_code = make_scenario([step(1, target_selector="current_position", on_success=["move_to:B"])])
    result = two_route_world().run(by_code)
    assert (result.furthest_asset_code, result.path_taken) == ("B", ["A", "B"])
    assert result.final_outcome == FinalOutcome.OBJECTIVE_REACHED

    by_role = make_scenario([step(1, target_selector="current_position", on_success=["move_to:server"])])
    assert two_route_world().run(by_role).furthest_asset_code == "B"

    nowhere = make_scenario([step(1, target_selector="current_position", on_success=["move_to:iot"])])
    with pytest.raises(EngineError, match="move_to:iot matches no asset"):
        two_route_world().run(nowhere)


def test_unreachable_target_and_empty_selector_block_the_step() -> None:
    island = make_world([make_asset("A"), make_asset("B")], [])
    result = island.run(ONE_STEP)
    assert result.step_results[0].note == "no path from A to B"
    assert result.step_results[0].target_code == "B"

    selector = make_scenario([step(1, target_selector="role:database")])
    assert island.run(selector).step_results[0].note == "no reachable target for role:database"


def test_missing_named_asset_raises_engine_error() -> None:
    with pytest.raises(EngineError, match="asset B does not exist"):
        make_world([make_asset("A")], []).run(ONE_STEP)
    with pytest.raises(EngineError, match="asset A does not exist"):
        make_world([make_asset("B")], []).run(ONE_STEP)


def equal_routes_world() -> World:
    assets = [make_asset("A"), make_asset("X", "router"), make_asset("Y", "router"), make_asset("B")]
    links = [make_link("L1", "A", "X"), make_link("L2", "X", "B"), make_link("L3", "A", "Y"), make_link("L4", "Y", "B")]
    return make_world(assets, links)


def test_equal_length_paths_are_ordered_by_the_seed() -> None:
    world = equal_routes_world()
    chosen = {seed: tuple(world.run(ONE_STEP, seed=seed).step_results[0].chosen_path) for seed in range(20)}
    assert set(chosen.values()) == {("A", "X", "B"), ("A", "Y", "B")}
    for seed in range(20):
        assert tuple(world.run(ONE_STEP, seed=seed).step_results[0].chosen_path) == chosen[seed]

    paths = engine.candidate_paths(world.graph, "A", "A", random.Random(1))
    assert [(path.asset_ids, path.hops) for path in paths] == [(["A"], 0)]


def test_same_seed_gives_byte_identical_results() -> None:
    scenario = make_scenario(
        [step(1, target_code="B", port=80, on_success=["gain_foothold"]), step(2, "T1005", target_selector="current_position", on_success=["read_data"])]
    )
    world = equal_routes_world()
    first, second = world.run(scenario, seed=11), world.run(scenario, seed=11)
    assert first.model_dump_json() == second.model_dump_json()
    offsets = [item.offset_seconds for item in first.step_results]
    assert offsets == sorted(offsets) and offsets[0] > 0


def test_step_time_is_base_time_within_twenty_percent() -> None:
    rng = random.Random(3)
    for tactic, base in timing.BASE_SECONDS.items():
        for _ in range(50):
            assert base * 0.8 <= timing.step_seconds(tactic, rng) <= base * 1.2
    assert timing.step_seconds(next(iter(timing.BASE_SECONDS)), random.Random(9)) == timing.step_seconds(
        next(iter(timing.BASE_SECONDS)), random.Random(9)
    )


async def test_run_fails_closed_when_the_network_does_not_fit_the_scenario(database: Any) -> None:
    network = await repository.insert_network(Network(name="empty"))
    result = await engine.run(network.id, "S1", seed=1)

    assert result.status == RunStatus.FAILED
    assert result.error == "EngineError: asset GUEST-DEV does not exist in this network"
    assert result.step_results == [] and result.final_outcome is None
    assert (result.network_version, result.scenario_code, result.seed) == (1, "S1", 1)
    assert result.finished_at is not None

    stored = await run_repository.get_run(result.id)
    assert stored == result


async def test_unexpected_engine_error_is_captured_not_half_saved(
    acme_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "simulate", explode)
    result = await engine.run(acme_id, "S3")
    assert (result.status, result.error) == (RunStatus.FAILED, "RuntimeError: boom")
    assert result.step_results == [] and result.path_taken == [] and result.effects_gained == []
    runs, total = await run_repository.list_runs(acme_id, 10, 0)
    assert total == 1 and runs[0].status == RunStatus.FAILED


async def test_unknown_network_or_scenario_is_not_found_and_stores_nothing(acme_id: str) -> None:
    with pytest.raises(NotFound):
        await engine.run("missing", "S1")
    with pytest.raises(NotFound):
        await engine.run(acme_id, "S99")
    assert (await run_repository.list_runs(acme_id, 10, 0))[1] == 0
    with pytest.raises(NotFound):
        await run_repository.get_run("missing")
