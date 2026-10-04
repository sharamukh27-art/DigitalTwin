"""Weakest link: the single failure that let an attack go furthest."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from app.controls import catalog
from app.models.analysis import WeakestLink
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.enums import CapabilityAction, ControlOutcome, StepOutcome, WeakestLinkKind
from app.models.run import StepResult

_KIND_ORDER = {
    WeakestLinkKind.MISSED_CONTROL: 0,
    WeakestLinkKind.CONNECTIVITY_HOLE: 1,
    WeakestLinkKind.BLIND_SPOT: 2,
}


@dataclass(frozen=True)
class Candidate:
    """One failure at a step the attacker got through.

    `reach` is how many steps the attack completed from that step on, or 0 when
    fixing the failure would not have stopped the attack.
    """

    kind: WeakestLinkKind
    ref: str
    step_order: int
    reach: int
    confidence: float
    explanation: str


def is_blind_spot(step: StepResult) -> bool:
    """Return True when traffic was allowed and no control was applicable to the step."""
    return (
        step.connectivity is not None
        and step.connectivity.allowed
        and all(item.outcome == ControlOutcome.NOT_APPLICABLE for item in step.control_results)
    )


def collect_candidates(
    steps: Sequence[StepResult],
    controls: Mapping[str, SecurityControl],
    assets: Mapping[str, Asset],
) -> list[Candidate]:
    """List every failure at steps that were not blocked.

    missed_control: a control with outcome `missed`, or one that only detected because
    its mode downgraded a block. connectivity_hole: the step crossed zones and no
    firewall or segmentation rule decided it. blind_spot: no control was applicable.
    `controls` and `assets` are keyed by code.
    """
    passed = [step for step in steps if step.outcome != StepOutcome.BLOCKED]
    candidates: list[Candidate] = []
    for index, step in enumerate(passed):
        reach = len(passed) - index
        where = f"step {step.step_order} ({step.technique_id} against {step.target_code})"

        for result in step.control_results:
            control = controls.get(result.control_code)
            capability = (
                catalog.get_capability(control.type, step.technique_id) if control is not None else None
            )
            if control is None or capability is None:
                continue
            action, downgraded_from = catalog.effective_action(capability, control.config)
            if result.outcome == ControlOutcome.MISSED:
                stops = action == CapabilityAction.BLOCK
                consequence = "would have blocked it" if stops else f"would only {action.value} it"
                candidates.append(
                    Candidate(
                        WeakestLinkKind.MISSED_CONTROL,
                        control.code,
                        step.step_order,
                        reach if stops else 0,
                        capability.confidence,
                        f"{control.code} missed {where}: {result.reason}. "
                        f"With that fixed it {consequence}.",
                    )
                )
            elif result.outcome == ControlOutcome.DETECTED and downgraded_from is not None:
                mode = getattr(control.config, "mode").value
                candidates.append(
                    Candidate(
                        WeakestLinkKind.MISSED_CONTROL,
                        control.code,
                        step.step_order,
                        reach,
                        capability.confidence,
                        f"{control.code} saw {where} but runs in {mode} mode, so it did not block it.",
                    )
                )

        connectivity = step.connectivity
        source, target = assets.get(step.source_code), assets.get(step.target_code or "")
        if (
            connectivity is not None
            and connectivity.allowed
            and connectivity.deciding_control_code is None
            and source is not None
            and target is not None
            and source.zone != target.zone
        ):
            candidates.append(
                Candidate(
                    WeakestLinkKind.CONNECTIVITY_HOLE,
                    f"{source.code}->{target.code}",
                    step.step_order,
                    reach,
                    0.0,
                    f"No firewall or segmentation rule decided {where}: traffic from "
                    f"{source.zone.value} to {target.zone.value} was not filtered.",
                )
            )

        if is_blind_spot(step):
            candidates.append(
                Candidate(
                    WeakestLinkKind.BLIND_SPOT,
                    step.technique_id,
                    step.step_order,
                    reach,
                    0.0,
                    f"No control was applicable to {where}.",
                )
            )
    return candidates


def rank(candidates: Sequence[Candidate]) -> list[Candidate]:
    """Order candidates: largest reach, then earliest step, lowest confidence, kind, ref."""
    return sorted(
        candidates,
        key=lambda item: (
            -item.reach,
            item.step_order,
            item.confidence,
            _KIND_ORDER[item.kind],
            item.ref,
        ),
    )


def find_weakest_link(
    steps: Sequence[StepResult],
    controls: Mapping[str, SecurityControl],
    assets: Mapping[str, Asset],
) -> WeakestLink | None:
    """Return the top-ranked failure, or None when nothing failed."""
    ranked = rank(collect_candidates(steps, controls, assets))
    if not ranked:
        return None
    best = ranked[0]
    return WeakestLink(
        kind=best.kind, ref=best.ref, step_order=best.step_order, explanation=best.explanation
    )
