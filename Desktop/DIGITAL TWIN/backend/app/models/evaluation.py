"""Models for control evaluation, connectivity checks and the coverage matrix."""

from typing import Any

from pydantic import BaseModel, Field

from app.models.asset import Asset
from app.models.common import PortNumber
from app.models.enums import (
    CapabilityAction,
    ControlOutcome,
    ControlType,
    CoverageStatus,
    PlacementKind,
    Protocol,
    Tactic,
    Zone,
)
from app.models.link import Link


class StepContext(BaseModel):
    """Everything the evaluator needs to know about one attack step."""

    technique_id: str
    source_asset: Asset
    target_asset: Asset
    link: Link | None = None
    path_asset_ids: list[str]
    layer: int = Field(ge=2, le=7)
    protocol: Protocol = Protocol.ANY
    port: PortNumber | None = None
    service: str | None = None


class ConnectivityResult(BaseModel):
    """Whether traffic for a step is allowed at all, and which control decided."""

    allowed: bool
    deciding_control_id: str | None = None
    rule_index: int | None = None
    reason: str


class ControlResult(BaseModel):
    """Outcome of one control against one step."""

    control_id: str
    control_code: str
    outcome: ControlOutcome
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


class EvaluateRequest(BaseModel):
    """Body of the debug evaluate endpoint. Assets are referenced by id."""

    technique_id: str
    source_asset_id: str
    target_asset_id: str
    protocol: Protocol = Protocol.TCP
    port: PortNumber | None = None
    service: str | None = None
    path_asset_ids: list[str] | None = Field(
        default=None, description="Route to evaluate. Defaults to the shortest path."
    )


class EvaluateResponse(BaseModel):
    """Connectivity decision and every control result for one step."""

    context: StepContext
    connectivity: ConnectivityResult
    results: list[ControlResult]


class ControlTypeInfo(BaseModel):
    """One control type with the JSON schema of its config."""

    type: ControlType
    min_layer: int
    techniques: list[str]
    config_schema: dict[str, Any]


class CoverageCell(BaseModel):
    """What one control can do about one technique, ignoring placement."""

    control_id: str
    control_code: str
    action: CapabilityAction | None = None
    confidence: float = 0.0
    status: CoverageStatus
    reason: str | None = None
    downgraded_from: CapabilityAction | None = None


class CoverageRow(BaseModel):
    """Coverage of one technique across all controls of a network."""

    technique_id: str
    technique_name: str
    tactic: Tactic
    cells: list[CoverageCell]


class PlacementGap(BaseModel):
    """A place a deployed control type does not reach."""

    kind: PlacementKind
    control_type: ControlType
    asset_id: str | None = None
    asset_code: str | None = None
    zone: Zone | None = None
    reason: str


class CoverageResponse(BaseModel):
    """Coverage matrix of a network."""

    matrix: list[CoverageRow]
    uncovered_techniques: list[str]
    weakly_covered: list[str]
    coverage_percent: float
    placement_gaps: list[PlacementGap]
