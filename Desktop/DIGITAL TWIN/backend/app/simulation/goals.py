"""Goal and final outcome checks for a finished attack chain."""

from collections.abc import Sequence

from app.models.asset import Asset
from app.models.enums import ZONE_TRUST, EffectKind, FinalOutcome, GoalKind, Zone
from app.models.scenario import ScenarioGoal

EffectLog = Sequence[tuple[EffectKind, Asset]]


def goal_reached(goal: ScenarioGoal, positions: Sequence[Asset], effect_log: EffectLog) -> bool:
    """Return True when the goal condition is met.

    `positions` are the assets the attacker stood on, entry first. `effect_log` lists
    each effect that landed with the asset it landed on.

    reach_asset: the attacker stood on the target.
    reach_any_critical: stood on an asset at or above min_criticality other than the entry.
    exfiltrate: exfiltrate_data landed.
    encrypt: encrypt_data landed on an asset at or above min_criticality.
    """
    if goal.kind == GoalKind.REACH_ASSET:
        return any(asset.code == goal.target_code for asset in positions)
    if goal.kind == GoalKind.REACH_ANY_CRITICAL:
        minimum = goal.min_criticality or 1
        entry_id = positions[0].id if positions else None
        return any(asset.criticality >= minimum and asset.id != entry_id for asset in positions)
    if goal.kind == GoalKind.EXFILTRATE:
        return any(kind == EffectKind.EXFILTRATE_DATA for kind, _ in effect_log)
    minimum = goal.min_criticality or 1
    return any(
        kind == EffectKind.ENCRYPT_DATA and asset.criticality >= minimum for kind, asset in effect_log
    )


def final_outcome(reached: bool, anything_landed: bool) -> FinalOutcome:
    """Classify a run.

    objective_reached: the goal was met. contained: the attacker gained no effect and
    never left the entry asset. partially_contained: something landed but the goal was not met.
    """
    if reached:
        return FinalOutcome.OBJECTIVE_REACHED
    return FinalOutcome.PARTIALLY_CONTAINED if anything_landed else FinalOutcome.CONTAINED


def deepest_zone(positions: Sequence[Asset]) -> Zone:
    """Return the most trusted zone among the assets the attacker stood on."""
    return max((asset.zone for asset in positions), key=lambda zone: ZONE_TRUST[zone])
