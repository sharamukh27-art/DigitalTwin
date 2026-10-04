"""Technique capability: can a control detect, block or log a specific step?

The evaluator is deterministic and does not roll dice. It reports what each control
could do and with what confidence; a later phase decides outcomes with a seeded RNG.
Connectivity enforcement is a separate concern, see connectivity.py.
"""

from collections.abc import Sequence

from app.controls import catalog
from app.controls.connectivity import check_connectivity
from app.models.control import MfaConfig, SecurityControl
from app.models.enums import CapabilityAction, ControlOutcome, PlacementKind
from app.models.evaluation import ControlResult, StepContext

__all__ = ["check_connectivity", "evaluate_all", "evaluate_capability", "visibility_gap"]

_OUTCOME_ORDER: dict[ControlOutcome, int] = {
    ControlOutcome.BLOCKED: 0,
    ControlOutcome.DETECTED: 1,
    ControlOutcome.LOGGED: 2,
    ControlOutcome.MISSED: 3,
    ControlOutcome.NOT_APPLICABLE: 4,
}

_ACTION_OUTCOME: dict[CapabilityAction, ControlOutcome] = {
    CapabilityAction.BLOCK: ControlOutcome.BLOCKED,
    CapabilityAction.DETECT: ControlOutcome.DETECTED,
    CapabilityAction.LOG: ControlOutcome.LOGGED,
}

_ACTION_VERB: dict[CapabilityAction, str] = {
    CapabilityAction.BLOCK: "blocks",
    CapabilityAction.DETECT: "detects",
    CapabilityAction.LOG: "logs",
}


def visibility_gap(control: SecurityControl, ctx: StepContext) -> str | None:
    """Return why the control's placement cannot see the step, or None when it can.

    An inline control sees a step that passes through or targets one of its assets.
    Traffic that merely starts at one of them is not inspected.
    """
    placement = control.placement
    source, target = ctx.source_asset, ctx.target_asset

    if placement.kind == PlacementKind.INLINE:
        beyond_source = ctx.path_asset_ids[1:]
        on_path = any(asset_id in placement.asset_ids for asset_id in beyond_source)
        if not on_path and target.id not in placement.asset_ids:
            return f"{control.code} is not on the path and does not protect {target.code}"
        return None

    if placement.kind == PlacementKind.SENSOR:
        if source.zone not in placement.zones and target.zone not in placement.zones:
            zones = " or ".join(sorted({source.zone.value, target.zone.value}))
            return f"zone not watched: {control.code} has no sensor in {zones}"
        return None

    if placement.kind == PlacementKind.HOST:
        if target.id not in placement.asset_ids:
            return f"{control.code} is not installed on {target.code}"
        return None

    if placement.kind == PlacementKind.IDENTITY:
        if ctx.service is None:
            return f"step has no service for {control.code} to protect"
        if ctx.service not in placement.services:
            return f"service {ctx.service} is not protected by {control.code}"
        if isinstance(control.config, MfaConfig) and ctx.service not in control.config.enforced_for:
            return f"service {ctx.service} is not in enforced_for of {control.code}"
        return None

    return None


def _result(
    control: SecurityControl, outcome: ControlOutcome, reason: str, confidence: float = 0.0
) -> ControlResult:
    return ControlResult(
        control_id=control.id,
        control_code=control.code,
        outcome=outcome,
        confidence=confidence,
        reason=reason,
    )


def evaluate_capability(control: SecurityControl, ctx: StepContext) -> ControlResult:
    """Evaluate one control against one step.

    Checks run in this order and the first that applies decides:
    1. control disabled -> not_applicable
    2. placement cannot see the step -> not_applicable
    3. technique works below the control's lowest layer -> not_applicable
    4. no catalog entry for the technique -> not_applicable
    5. a `requires` condition fails -> missed
    6. otherwise detected, blocked or logged with the catalog confidence
    """
    if not control.enabled:
        return _result(control, ControlOutcome.NOT_APPLICABLE, "control disabled")

    gap = visibility_gap(control, ctx)
    if gap is not None:
        return _result(control, ControlOutcome.NOT_APPLICABLE, gap)

    lowest = catalog.min_layer(control.type)
    if ctx.layer < lowest:
        return _result(
            control,
            ControlOutcome.NOT_APPLICABLE,
            f"{ctx.technique_id} works at layer {ctx.layer}, "
            f"below layer {lowest} where {control.type.value} operates",
        )

    capability = catalog.get_capability(control.type, ctx.technique_id)
    if capability is None:
        return _result(
            control,
            ControlOutcome.NOT_APPLICABLE,
            f"{control.type.value} has no capability for {ctx.technique_id}",
        )

    failures = catalog.failed_requirements(capability, control.config)
    if failures:
        return _result(control, ControlOutcome.MISSED, f"{' and '.join(failures)} on {control.code}")

    action, downgraded_from = catalog.effective_action(capability, control.config)
    reason = f"{control.code} {_ACTION_VERB[action]} {ctx.technique_id}"
    if downgraded_from is not None:
        mode = getattr(control.config, "mode").value
        reason += f" (would {downgraded_from.value}, but mode is {mode})"
    return _result(control, _ACTION_OUTCOME[action], reason, capability.confidence)


def evaluate_all(controls: Sequence[SecurityControl], ctx: StepContext) -> list[ControlResult]:
    """Evaluate every control against a step.

    Sorted blocked, detected, logged, missed, not_applicable; then by confidence
    (highest first) and control code.
    """
    results = [evaluate_capability(control, ctx) for control in controls]
    return sorted(
        results,
        key=lambda item: (_OUTCOME_ORDER[item.outcome], -item.confidence, item.control_code),
    )
