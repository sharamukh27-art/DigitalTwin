"""Simulation run models: results of running a scenario against a twin."""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.models.common import new_id, utcnow
from app.models.enums import ControlOutcome, FinalOutcome, RunStatus, StepOutcome, Tactic, Zone
from app.models.evaluation import ControlResult

DEFAULT_SEED = 42


class StepConnectivity(BaseModel):
    """Connectivity decision for the path a step used."""

    allowed: bool
    deciding_control_code: str | None = None
    reason: str


class FirstDetection(BaseModel):
    """The earliest step at which any control blocked, detected or logged the attack."""

    step_order: int
    control_code: str
    offset_seconds: int


class StepResult(BaseModel):
    """What happened at one step of a run."""

    step_order: int
    technique_id: str
    technique_name: str
    tactic: Tactic
    source_code: str
    target_code: str | None = None
    link_code: str | None = None
    connectivity: StepConnectivity | None = None
    control_results: list[ControlResult] = Field(default_factory=list)
    outcome: StepOutcome
    chosen_path: list[str] = Field(default_factory=list)
    alternatives_tried: int = 0
    offset_seconds: int
    effects_applied: list[str] = Field(default_factory=list)
    position_after: str
    note: str = ""


class SimulationOutcome(BaseModel):
    """Everything the engine computes for a run, before it is stamped and stored."""

    step_results: list[StepResult]
    final_outcome: FinalOutcome
    furthest_asset_code: str
    deepest_zone: Zone
    path_taken: list[str]
    effects_gained: list[str]
    first_detection: FirstDetection | None = None


class SimulationRun(BaseModel):
    """A stored, immutable simulation run."""

    id: str = Field(default_factory=new_id)
    network_id: str
    network_version: int
    scenario_id: str
    scenario_code: str
    seed: int
    status: RunStatus
    started_at: datetime
    finished_at: datetime | None = None
    step_results: list[StepResult] = Field(default_factory=list)
    final_outcome: FinalOutcome | None = None
    furthest_asset_code: str | None = None
    deepest_zone: Zone | None = None
    path_taken: list[str] = Field(default_factory=list)
    effects_gained: list[str] = Field(default_factory=list)
    first_detection: FirstDetection | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("started_at", "finished_at", "created_at")
    @classmethod
    def _ensure_utc(cls, value: datetime | None) -> datetime | None:
        """Treat naive datetimes as UTC and convert aware ones to UTC."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def to_document(self) -> dict[str, Any]:
        """Return a MongoDB-ready dict: plain JSON values, native datetimes."""
        document = self.model_dump(mode="json")
        for field in ("started_at", "finished_at", "created_at"):
            document[field] = getattr(self, field)
        return document


class SimulateRequest(BaseModel):
    """Body of POST /networks/{id}/simulate. `scenario_id` may be an id or a code."""

    scenario_id: str
    seed: int = DEFAULT_SEED


class SimulateAllRequest(BaseModel):
    """Body of POST /networks/{id}/simulate-all."""

    seed: int = DEFAULT_SEED


class RunSummary(BaseModel):
    """Short view of a run for lists."""

    id: str
    network_id: str
    network_version: int
    scenario_id: str
    scenario_code: str
    seed: int
    status: RunStatus
    final_outcome: FinalOutcome | None = None
    furthest_asset_code: str | None = None
    deepest_zone: Zone | None = None
    steps_executed: int
    steps_blocked: int
    steps_detected: int
    first_detection: FirstDetection | None = None
    error: str | None = None
    created_at: datetime

    @classmethod
    def from_run(cls, run: SimulationRun) -> "RunSummary":
        """Build a summary from a full run."""
        outcomes = [step.outcome for step in run.step_results]
        return cls(
            **run.model_dump(
                include={
                    "id", "network_id", "network_version", "scenario_id", "scenario_code", "seed",
                    "status", "final_outcome", "furthest_asset_code", "deepest_zone",
                    "first_detection", "error", "created_at",
                }
            ),
            steps_executed=len(outcomes),
            steps_blocked=outcomes.count(StepOutcome.BLOCKED),
            steps_detected=outcomes.count(StepOutcome.DETECTED_NOT_BLOCKED),
        )


class SimulateAllResponse(BaseModel):
    """Response of POST /networks/{id}/simulate-all."""

    network_id: str
    network_version: int
    seed: int
    runs: list[RunSummary]


class ControlBadge(BaseModel):
    """A control that reacted to a step, for display next to the step."""

    control_code: str
    outcome: ControlOutcome
    confidence: float


class RunEvent(BaseModel):
    """One item of the replay stream of a run."""

    sequence: int
    type: Literal["start", "step", "end"]
    offset_seconds: int
    title: str
    step_order: int | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: Tactic | None = None
    source_code: str | None = None
    target_code: str | None = None
    outcome: str | None = None
    connectivity_allowed: bool | None = None
    control_badges: list[ControlBadge] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    cumulative_path: list[str] = Field(default_factory=list)
    effects: list[str] = Field(default_factory=list)
    position: str | None = None
    note: str = ""


class RunEventsResponse(BaseModel):
    """Response of GET /runs/{id}/events."""

    run_id: str
    scenario_code: str
    status: RunStatus
    events: list[RunEvent]
