"""Target resolution: turn a step's target code or selector into an asset of the twin."""

import random
from collections.abc import Iterable, Mapping

import networkx as nx

from app.models.asset import Asset
from app.models.enums import AssetType, GoalKind, SelectorKind, Zone
from app.models.scenario import ScenarioEntry, ScenarioGoal, ScenarioStep, parse_selector

NETWORK_DEVICE_TYPES = frozenset(
    {AssetType.ROUTER, AssetType.SWITCH, AssetType.FIREWALL, AssetType.ACCESS_POINT}
)


class EngineError(Exception):
    """The scenario cannot run on this network at all, for example a named asset is missing."""


class TargetNotFound(Exception):
    """A selector matched nothing the attacker can reach. The step is blocked."""


def is_host(asset: Asset) -> bool:
    """Return True for endpoints and servers, False for network devices."""
    return asset.type not in NETWORK_DEVICE_TYPES


def asset_by_code(assets: Mapping[str, Asset], code: str) -> Asset:
    """Return the asset with a code. Raises EngineError when the network has none."""
    for asset in assets.values():
        if asset.code == code:
            return asset
    raise EngineError(f"asset {code} does not exist in this network")


def resolve_entry(entry: ScenarioEntry, assets: Mapping[str, Asset]) -> Asset:
    """Return the asset the attacker starts on.

    A zone entry picks the zone's attacker node if it has one, otherwise its first
    asset by code.
    """
    if entry.asset_code is not None:
        return asset_by_code(assets, entry.asset_code)
    in_zone = [asset for asset in assets.values() if asset.zone == entry.zone]
    if not in_zone:
        raise EngineError(f"zone {entry.zone.value if entry.zone else ''} has no assets in this network")
    return min(in_zone, key=lambda asset: (asset.type != AssetType.ATTACKER_NODE, asset.code))


def nearest(
    graph: nx.MultiDiGraph,
    position: str,
    candidates: Iterable[str],
    assets: Mapping[str, Asset],
    rng: random.Random,
) -> str | None:
    """Return the reachable candidate with the fewest hops from the position.

    The position itself is never returned. Ties are broken with the seeded RNG.
    """
    distances = nx.single_source_shortest_path_length(graph, position)
    reachable = [item for item in candidates if item in distances and item != position]
    if not reachable:
        return None
    best = min(distances[item] for item in reachable)
    tied = sorted(
        (item for item in reachable if distances[item] == best), key=lambda item: assets[item].code
    )
    return tied[0] if len(tied) == 1 else rng.choice(tied)


def goal_asset_id(
    goal: ScenarioGoal,
    graph: nx.MultiDiGraph,
    assets: Mapping[str, Asset],
    position: str,
    entry_id: str,
    rng: random.Random,
) -> str | None:
    """Return the asset the attacker should head for, or None when nothing qualifies.

    reach_asset: the named asset. reach_any_critical and encrypt: the nearest host at
    or above min_criticality other than the entry. exfiltrate: the nearest internet asset.
    """
    if goal.kind == GoalKind.REACH_ASSET and goal.target_code is not None:
        return asset_by_code(assets, goal.target_code).id
    if goal.kind == GoalKind.EXFILTRATE:
        candidates = [asset.id for asset in assets.values() if asset.zone == Zone.INTERNET]
    else:
        minimum = goal.min_criticality or 1
        candidates = [
            asset.id
            for asset in assets.values()
            if is_host(asset) and asset.criticality >= minimum and asset.id != entry_id
        ]
    here = assets[position]
    if position in candidates:
        return here.id
    return nearest(graph, position, candidates, assets, rng)


def resolve_target(
    step: ScenarioStep,
    goal: ScenarioGoal,
    graph: nx.MultiDiGraph,
    assets: Mapping[str, Asset],
    position: str,
    entry_id: str,
    rng: random.Random,
) -> str:
    """Return the id of the asset a step targets.

    target_code: that asset (EngineError when the network has none).
    current_position: where the attacker is.
    role:<asset_type>: the nearest asset of that type.
    any_in_zone:<zone>: the nearest host in the zone (network devices are skipped).
    next_hop_toward_goal: the first host on the shortest path to the goal asset.

    Raises TargetNotFound when a selector matches nothing reachable.
    """
    if step.target_code is not None:
        return asset_by_code(assets, step.target_code).id

    selector = step.target_selector or ""
    kind, argument = parse_selector(selector)

    if kind == SelectorKind.CURRENT_POSITION:
        return position

    if kind == SelectorKind.NEXT_HOP_TOWARD_GOAL:
        goal_id = goal_asset_id(goal, graph, assets, position, entry_id, rng)
        if goal_id is None:
            raise TargetNotFound("no reachable asset satisfies the goal")
        if goal_id == position:
            return position
        try:
            path: list[str] = nx.shortest_path(graph, position, goal_id)
        except nx.NetworkXNoPath as exc:
            raise TargetNotFound(
                f"no path from {assets[position].code} toward {assets[goal_id].code}"
            ) from exc
        return next((node for node in path[1:] if is_host(assets[node])), goal_id)

    if kind == SelectorKind.ROLE:
        candidates = [asset.id for asset in assets.values() if asset.type.value == argument]
    else:
        candidates = [
            asset.id for asset in assets.values() if asset.zone.value == argument and is_host(asset)
        ]
    target = nearest(graph, position, candidates, assets, rng)
    if target is None:
        raise TargetNotFound(f"no reachable target for {selector}")
    return target
