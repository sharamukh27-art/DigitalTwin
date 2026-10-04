"""Remediation models: proposed fixes, their verification, approval and the audit log."""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.models.common import Name, StoredModel, new_id, utcnow
from app.models.enums import (
    EffortHint,
    FinalOutcome,
    PatchTarget,
    RemediationRule,
    RemediationStatus,
)
from app.models.whatif import PatchOp, WhatIfDiff

SYSTEM_ACTOR = "system"
EFFORT_WEIGHT: dict[EffortHint, int] = {EffortHint.LOW: 1, EffortHint.MEDIUM: 2, EffortHint.HIGH: 3}


class RemediationTarget(BaseModel):
    """The control or asset a remediation changes."""

    kind: PatchTarget
    code: str


class RemediationCitation(BaseModel):
    """A knowledge base source that supports a remediation."""

    id: str
    source_name: str
    source_url: str
    section_id: str


class ScenarioOutcome(BaseModel):
    """Risk and containment of one scenario on one side of a verification."""

    scenario_code: str
    risk_score: int
    containment: FinalOutcome


class VerificationSide(BaseModel):
    """All scenarios before or after a patch."""

    per_scenario: list[ScenarioOutcome]
    average_risk: float
    posture_score: int


class Verification(BaseModel):
    """Result of testing a patch on a sandbox copy of the network."""

    verified: bool
    reasons: list[str] = Field(default_factory=list)
    network_version: int
    seed: int
    before: VerificationSide
    after: VerificationSide
    diff: list[WhatIfDiff]


class Candidate(BaseModel):
    """A fix produced by a rule, before it gets its text and is stored."""

    rule: RemediationRule
    target: RemediationTarget
    patch: list[PatchOp]
    config_snippet: str
    effort: EffortHint
    technique_id: str
    step_order: int
    template_title: str
    template_rationale: str
    affected_assets: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class Remediation(StoredModel):
    """A proposed change to the twin, with how it was tested and decided.

    The patch comes from a deterministic rule. Only `title` and `rationale` may be
    written by the LLM.
    """

    network_id: str
    run_id: str
    scenario_code: str
    technique_id: str
    rule: RemediationRule
    title: str
    rationale: str
    text_generated_by: str = "template"
    target: RemediationTarget
    affected_assets: list[str] = Field(default_factory=list)
    patch: list[PatchOp]
    fingerprint: str
    config_snippet: str
    citations: list[RemediationCitation] = Field(default_factory=list)
    effort: EffortHint
    status: RemediationStatus = RemediationStatus.PROPOSED
    verification: Verification | None = None
    risk_reduction: float | None = None
    priority: float | None = None
    verified_network_version: int | None = None
    notes: list[str] = Field(default_factory=list)
    approved_by: str | None = None
    approved_at: datetime | None = None


class RemediationUpdate(BaseModel):
    """Body of PATCH /remediations/{id}: a human decision."""

    status: Literal["approved", "rejected"]
    actor: Name
    note: str = ""


class BundleRequest(BaseModel):
    """Body of POST /remediations/verify-bundle."""

    ids: list[str] = Field(min_length=1)


class BundleResult(BaseModel):
    """Combined effect of applying several remediations together."""

    remediation_ids: list[str]
    network_id: str
    patch: list[PatchOp]
    verification: Verification
    risk_reduction: float
    individual_risk_reductions: dict[str, float | None]


class AuditLog(BaseModel):
    """One recorded state change."""

    id: str = Field(default_factory=new_id)
    network_id: str
    actor: str
    action: str
    target: str
    before_hash: str
    after_hash: str
    note: str = ""
    at: datetime = Field(default_factory=utcnow)

    @field_validator("at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        """Treat naive datetimes as UTC and convert aware ones to UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def to_document(self) -> dict[str, Any]:
        """Return a MongoDB-ready dict: plain JSON values, native datetime."""
        document = self.model_dump(mode="json")
        document["at"] = self.at
        return document
