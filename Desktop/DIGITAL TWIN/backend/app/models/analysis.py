"""Analysis models: findings, risk score and network posture."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.asset import Asset
from app.models.common import new_id, utcnow
from app.models.control import SecurityControl
from app.models.enums import (
    AttackerProfile,
    DataClassification,
    FinalOutcome,
    RiskBand,
    StepOutcome,
    Tactic,
    WeakestLinkKind,
)
from app.models.network import Network


class TwinSnapshot(BaseModel):
    """A network with its assets and controls, as the analysis functions need it."""

    network: Network
    assets: list[Asset]
    controls: list[SecurityControl]


class ControlRef(BaseModel):
    """A control named in findings."""

    code: str
    name: str


class MissedControl(BaseModel):
    """A control that could have acted on a step but failed a requirement."""

    code: str
    name: str
    step_order: int
    technique_id: str
    reason: str


class NotSeenGap(BaseModel):
    """A step no control was even applicable to: a blind spot."""

    technique_id: str
    step_order: int
    note: str


class AttackDepth(BaseModel):
    """How far through the scenario the attack got."""

    hops_achieved: int
    total_steps: int
    ratio: float


class BlastRadius(BaseModel):
    """Assets the attacker stood on or successfully acted against."""

    asset_codes: list[str] = Field(default_factory=list)
    count: int = 0
    criticality_sum: int = 0
    max_criticality: int = 0
    data_assets_reached: list[str] = Field(default_factory=list)
    max_cvss: float = 0.0
    max_data_classification: DataClassification | None = None


class WeakestLink(BaseModel):
    """The single failure that let the attack go furthest."""

    kind: WeakestLinkKind
    ref: str
    step_order: int
    explanation: str


class KillchainStep(BaseModel):
    """One step of the run, reduced to what a kill chain view needs."""

    step_order: int
    tactic: Tactic
    technique_id: str
    outcome: StepOutcome


class Findings(BaseModel):
    """Everything the analysis derives from one simulation run.

    Self-contained: the risk score is computed from this object alone.
    """

    id: str = Field(default_factory=new_id)
    run_id: str
    network_id: str
    scenario_code: str
    network_version: int
    attacker_profile: AttackerProfile
    containment: FinalOutcome
    first_detection_step: int | None = None
    time_to_detect_seconds: int | None = None
    first_block_step: int | None = None
    detecting_controls: list[ControlRef] = Field(default_factory=list)
    blocking_controls: list[ControlRef] = Field(default_factory=list)
    missed_controls: list[MissedControl] = Field(default_factory=list)
    not_seen_gaps: list[NotSeenGap] = Field(default_factory=list)
    attack_depth: AttackDepth
    blast_radius: BlastRadius
    effects_gained: list[str] = Field(default_factory=list)
    weakest_link: WeakestLink | None = None
    killchain: list[KillchainStep] = Field(default_factory=list)
    total_network_criticality: int = 0
    unrecoverable_encryption: bool = False
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("created_at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        """Treat naive datetimes as UTC and convert aware ones to UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def to_document(self) -> dict[str, Any]:
        """Return a MongoDB-ready dict: plain JSON values, native datetimes."""
        document = self.model_dump(mode="json")
        document["created_at"] = self.created_at
        return document


class RiskFactor(BaseModel):
    """One term of the likelihood or impact sum."""

    name: str
    raw: float
    weight: float
    contribution: float
    detail: str


class RiskBreakdown(BaseModel):
    """The full math behind a risk score."""

    likelihood_factors: list[RiskFactor]
    impact_factors: list[RiskFactor]
    formula: str
    constants: dict[str, Any]


class RiskScore(BaseModel):
    """Risk of one run: score 0-100 = round(likelihood x impact x 100)."""

    score: int = Field(ge=0, le=100)
    band: RiskBand
    likelihood: float
    impact: float
    breakdown: RiskBreakdown


class ScenarioRisk(BaseModel):
    """Risk and containment of one scenario on a network."""

    scenario_code: str
    run_id: str
    risk_score: int
    band: RiskBand
    containment: FinalOutcome
    weakest_link: WeakestLink | None = None


class WeakestLinkCount(BaseModel):
    """How many scenarios share the same weakest link."""

    kind: WeakestLinkKind
    ref: str
    count: int
    scenario_codes: list[str]


class PostureBreakdown(BaseModel):
    """The math behind the posture score."""

    average_risk: float
    base_score: float
    coverage_percent: float
    coverage_factor: float
    formula: str
    constants: dict[str, float]


class PostureSnapshot(BaseModel):
    """Posture of a network at one version, kept for the trend line."""

    network_id: str
    network_version: int
    posture_score: int
    average_risk: float
    coverage_percent: float
    scenarios_contained: int
    scenarios_partially_contained: int
    scenarios_reached: int
    recorded_at: datetime = Field(default_factory=utcnow)

    @field_validator("recorded_at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        """Treat naive datetimes as UTC and convert aware ones to UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Posture(BaseModel):
    """Security posture of a whole network. 100 is safest."""

    network_id: str
    network_version: int
    posture_score: int = Field(ge=0, le=100)
    per_scenario: list[ScenarioRisk]
    average_risk: float
    coverage_percent: float
    top_risks: list[ScenarioRisk]
    worst_weakest_links: list[WeakestLinkCount]
    stale_scenarios: list[str] = Field(default_factory=list)
    breakdown: PostureBreakdown
