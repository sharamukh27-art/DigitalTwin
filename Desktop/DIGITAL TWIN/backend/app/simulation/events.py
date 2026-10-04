"""Replay stream: turns a stored run into an ordered list of events for the frontend."""

from app.models.enums import ControlOutcome, RunStatus, StepOutcome
from app.models.run import ControlBadge, RunEvent, SimulationRun, StepResult


def _badges(step: StepResult) -> list[ControlBadge]:
    """Return the controls that reacted to a step, leaving out those it did not concern."""
    return [
        ControlBadge(
            control_code=result.control_code, outcome=result.outcome, confidence=result.confidence
        )
        for result in step.control_results
        if result.outcome != ControlOutcome.NOT_APPLICABLE
    ]


def build_events(run: SimulationRun) -> list[RunEvent]:
    """Return a start event, one event per step in order, and an end event.

    `cumulative_path` grows with every step that moved the attacker, so the frontend
    can draw the route so far at any point of the replay.
    """
    entry = run.path_taken[0] if run.path_taken else None
    if entry is None and run.step_results:
        entry = run.step_results[0].source_code
    cumulative: list[str] = [entry] if entry else []
    position = entry

    events = [
        RunEvent(
            sequence=0,
            type="start",
            offset_seconds=0,
            title=f"Scenario {run.scenario_code} starts" + (f" at {entry}" if entry else ""),
            cumulative_path=list(cumulative),
            position=entry,
        )
    ]

    for step in run.step_results:
        moved = step.outcome != StepOutcome.BLOCKED and step.position_after != position
        if moved:
            if step.chosen_path and step.chosen_path[-1] == step.position_after:
                cumulative.extend(step.chosen_path[1:])
            else:
                cumulative.append(step.position_after)
            position = step.position_after
        events.append(
            RunEvent(
                sequence=len(events),
                type="step",
                offset_seconds=step.offset_seconds,
                title=f"{step.technique_id} {step.technique_name}",
                step_order=step.step_order,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                tactic=step.tactic,
                source_code=step.source_code,
                target_code=step.target_code,
                outcome=step.outcome.value,
                connectivity_allowed=step.connectivity.allowed if step.connectivity else None,
                control_badges=_badges(step),
                path=step.chosen_path,
                cumulative_path=list(cumulative),
                effects=step.effects_applied,
                position=position,
                note=step.note,
            )
        )

    last_offset = run.step_results[-1].offset_seconds if run.step_results else 0
    if run.status == RunStatus.FAILED:
        title, outcome, note = "Simulation failed", RunStatus.FAILED.value, run.error or ""
    else:
        outcome = run.final_outcome.value if run.final_outcome else None
        title = f"Attack {outcome.replace('_', ' ')}" if outcome else "Simulation ended"
        note = f"furthest asset {run.furthest_asset_code}" if run.furthest_asset_code else ""
    events.append(
        RunEvent(
            sequence=len(events),
            type="end",
            offset_seconds=last_offset,
            title=title,
            outcome=outcome,
            cumulative_path=list(cumulative),
            effects=run.effects_gained,
            position=position,
            note=note,
        )
    )
    return events
