"""Target resolution and goal evaluation."""

import random
from typing import Any

import pytest

from app.models.enums import EffectKind, FinalOutcome, Zone
from app.models.scenario import ScenarioEntry, ScenarioGoal, ScenarioStep
from app.simulation import goals
from app.simulation.targeting import (
    EngineError,
    TargetNotFound,
    goal_asset_id,
    is_host,
    resolve_entry,
    resolve_target,
)
from tests.sim import World, load_world, make_asset, make_link, make_world, step


def make_step(**fields: Any) -> ScenarioStep:
    return ScenarioStep.model_validate(step(1, **fields))


def resolve(world: World, position: str, goal: ScenarioGoal, seed: int = 1, **fields: Any) -> str:
    assets = {asset.id: asset for asset in world.assets}
    target = resolve_target(
        make_step(**fields), goal, world.graph, assets, world.asset(position).id, world.asset(position).id, random.Random(seed)
    )
    return assets[target].code


REACH_DB = ScenarioGoal(kind="reach_asset", target_code="DB-01")


async def test_entry_resolution(acme_id: str) -> None:
    world = await load_world(acme_id)
    assets = {asset.id: asset for asset in world.assets}
    assert resolve_entry(ScenarioEntry(zone="internet"), assets).code == "INTERNET"
    assert resolve_entry(ScenarioEntry(zone="dmz"), assets).code == "FW-EDGE"
    assert resolve_entry(ScenarioEntry(asset_code="WS-03"), assets).code == "WS-03"
    with pytest.raises(EngineError, match="asset NOPE does not exist"):
        resolve_entry(ScenarioEntry(asset_code="NOPE"), assets)

    only_servers = {"A": make_asset("A")}
    with pytest.raises(EngineError, match="zone internet has no assets"):
        resolve_entry(ScenarioEntry(zone="internet"), only_servers)


async def test_code_and_current_position(acme_id: str) -> None:
    world = await load_world(acme_id)
    assert resolve(world, "INTERNET", REACH_DB, target_code="WEB-01") == "WEB-01"
    assert resolve(world, "WEB-01", REACH_DB, target_selector="current_position") == "WEB-01"
    with pytest.raises(EngineError):
        resolve(world, "INTERNET", REACH_DB, target_code="GHOST")


async def test_role_picks_the_nearest_and_breaks_ties_with_the_seed(acme_id: str) -> None:
    world = await load_world(acme_id)
    assert resolve(world, "WS-03", REACH_DB, target_selector="role:file_server") == "FS-01"
    assert resolve(world, "ADMIN-01", REACH_DB, target_selector="role:attacker_node") == "INTERNET"

    picks = {resolve(world, "GUEST-DEV", REACH_DB, seed=seed, target_selector="role:workstation") for seed in range(30)}
    assert picks == {"WS-06", "WS-07", "WS-08", "WS-09", "WS-10"}
    again = [resolve(world, "GUEST-DEV", REACH_DB, seed=5, target_selector="role:workstation") for _ in range(3)]
    assert len(set(again)) == 1

    with pytest.raises(TargetNotFound, match="no reachable target for role:iot"):
        resolve(world, "WS-03", REACH_DB, target_selector="role:iot")


async def test_any_in_zone_skips_network_devices(acme_id: str) -> None:
    world = await load_world(acme_id)
    corporate = {resolve(world, "INTERNET", REACH_DB, seed=seed, target_selector="any_in_zone:corporate") for seed in range(40)}
    assert corporate == {f"WS-{index:02d}" for index in range(1, 11)}
    servers = {resolve(world, "WS-08", REACH_DB, seed=seed, target_selector="any_in_zone:server") for seed in range(30)}
    assert servers == {"APP-01", "DB-01", "DC-01", "FS-01"}
    assert resolve(world, "INTERNET", REACH_DB, target_selector="any_in_zone:management") == "ADMIN-01"
    assert not is_host(world.asset("SW-CORE")) and is_host(world.asset("VPN-01"))


async def test_next_hop_toward_goal(acme_id: str) -> None:
    world = await load_world(acme_id)
    selector = {"target_selector": "next_hop_toward_goal"}
    assert resolve(world, "APP-01", REACH_DB, **selector) == "DB-01"
    assert resolve(world, "INTERNET", REACH_DB, **selector) == "DB-01"
    assert resolve(world, "DB-01", REACH_DB, **selector) == "DB-01"

    critical = ScenarioGoal(kind="reach_any_critical", min_criticality=5)
    assert {resolve(world, "VPN-01", critical, seed=seed, **selector) for seed in range(20)} == {"DB-01", "DC-01"}

    exfiltrate = ScenarioGoal(kind="exfiltrate")
    assert resolve(world, "FS-01", exfiltrate, **selector) == "INTERNET"


def test_next_hop_stops_at_the_first_host_on_the_way() -> None:
    world = make_world(
        [make_asset("A"), make_asset("SW", "switch"), make_asset("MID"), make_asset("B")],
        [make_link("L1", "A", "SW"), make_link("L2", "SW", "MID"), make_link("L3", "MID", "B")],
    )
    goal = ScenarioGoal(kind="reach_asset", target_code="B")
    assert resolve(world, "A", goal, target_selector="next_hop_toward_goal") == "MID"
    assert resolve(world, "MID", goal, target_selector="next_hop_toward_goal") == "B"


def test_unreachable_goal_raises_target_not_found() -> None:
    world = make_world([make_asset("A"), make_asset("B"), make_asset("C", criticality=5)], [])
    with pytest.raises(TargetNotFound, match="no path from A toward B"):
        resolve(world, "A", ScenarioGoal(kind="reach_asset", target_code="B"), target_selector="next_hop_toward_goal")
    with pytest.raises(TargetNotFound, match="no reachable asset satisfies the goal"):
        resolve(world, "A", ScenarioGoal(kind="reach_any_critical", min_criticality=5), target_selector="next_hop_toward_goal")

    assets = {asset.id: asset for asset in world.assets}
    goal = ScenarioGoal(kind="encrypt", min_criticality=5)
    assert goal_asset_id(goal, world.graph, assets, "C", "A", random.Random(1)) == "C"


LOW, HIGH, TOP = make_asset("LOW", criticality=2), make_asset("HIGH", criticality=4), make_asset("TOP", criticality=5)


def test_goal_reach_asset() -> None:
    goal = ScenarioGoal(kind="reach_asset", target_code="HIGH")
    assert goals.goal_reached(goal, [LOW, HIGH], []) is True
    assert goals.goal_reached(goal, [LOW, TOP], []) is False


def test_goal_reach_any_critical_ignores_the_entry() -> None:
    goal = ScenarioGoal(kind="reach_any_critical", min_criticality=4)
    assert goals.goal_reached(goal, [LOW, HIGH], []) is True
    assert goals.goal_reached(goal, [LOW], []) is False
    assert goals.goal_reached(goal, [TOP], []) is False
    assert goals.goal_reached(goal, [TOP, LOW], []) is False


def test_goal_exfiltrate() -> None:
    goal = ScenarioGoal(kind="exfiltrate")
    assert goals.goal_reached(goal, [LOW], [(EffectKind.READ_DATA, HIGH)]) is False
    assert goals.goal_reached(goal, [LOW], [(EffectKind.READ_DATA, HIGH), (EffectKind.EXFILTRATE_DATA, LOW)]) is True


def test_goal_encrypt_needs_a_critical_enough_asset() -> None:
    goal = ScenarioGoal(kind="encrypt", min_criticality=4)
    assert goals.goal_reached(goal, [LOW], [(EffectKind.ENCRYPT_DATA, LOW)]) is False
    assert goals.goal_reached(goal, [LOW], [(EffectKind.ENCRYPT_DATA, HIGH)]) is True
    assert goals.goal_reached(goal, [LOW, HIGH], [(EffectKind.READ_DATA, HIGH)]) is False


def test_final_outcome_and_deepest_zone() -> None:
    assert goals.final_outcome(True, True) == FinalOutcome.OBJECTIVE_REACHED
    assert goals.final_outcome(False, True) == FinalOutcome.PARTIALLY_CONTAINED
    assert goals.final_outcome(False, False) == FinalOutcome.CONTAINED

    visited = [make_asset("I", zone="internet"), make_asset("D", zone="dmz"), make_asset("S", zone="server"), make_asset("G", zone="guest")]
    assert goals.deepest_zone(visited) == Zone.SERVER
    assert goals.deepest_zone(visited[:1]) == Zone.INTERNET
