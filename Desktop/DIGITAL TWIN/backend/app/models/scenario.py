"""Scenario models: multi-step attack chains run against a twin."""

from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, model_validator

from app.models.asset import CriticalityLevel
from app.models.common import Code, Name, PortNumber
from app.models.enums import (
    AssetType,
    AttackerProfile,
    ControlType,
    EffectKind,
    GoalKind,
    Protocol,
    SelectorKind,
    Tactic,
    Zone,
)

_CONNECTIVITY_TYPES = frozenset({ControlType.FIREWALL, ControlType.SEGMENTATION})
_SELECTORS_WITHOUT_ARGUMENT = frozenset(
    {SelectorKind.NEXT_HOP_TOWARD_GOAL, SelectorKind.CURRENT_POSITION}
)


def parse_effect(value: str) -> tuple[EffectKind, str | None]:
    """Split an effect string into its kind and argument.

    Plain effects have no argument. `move_to:<code-or-role>` carries one.
    Raises ValueError for anything else.
    """
    name, separator, argument = value.partition(":")
    try:
        kind = EffectKind(name)
    except ValueError as exc:
        raise ValueError(f"unknown effect '{value}'") from exc
    if kind == EffectKind.MOVE_TO:
        if not argument:
            raise ValueError("move_to needs a target: move_to:<code-or-role>")
        return kind, argument
    if separator:
        raise ValueError(f"effect '{name}' takes no argument")
    return kind, None


def parse_selector(value: str) -> tuple[SelectorKind, str | None]:
    """Split a target selector into its kind and argument.

    Forms: next_hop_toward_goal, current_position, any_in_zone:<zone>, role:<asset_type>.
    Raises ValueError for anything else.
    """
    name, _, argument = value.partition(":")
    try:
        kind = SelectorKind(name)
    except ValueError as exc:
        raise ValueError(f"unknown target selector '{value}'") from exc
    if kind in _SELECTORS_WITHOUT_ARGUMENT:
        if argument:
            raise ValueError(f"selector '{name}' takes no argument")
        return kind, None
    try:
        if kind == SelectorKind.ANY_IN_ZONE:
            Zone(argument)
        else:
            AssetType(argument)
    except ValueError as exc:
        raise ValueError(f"selector '{value}' has an unknown argument") from exc
    return kind, argument


def _validate_effect(value: str) -> str:
    parse_effect(value)
    return value


def _validate_precondition(value: str) -> str:
    kind, _ = parse_effect(value)
    if kind == EffectKind.MOVE_TO:
        raise ValueError("move_to cannot be a precondition")
    return value


def _validate_selector(value: str) -> str:
    parse_selector(value)
    return value


Effect = Annotated[str, AfterValidator(_validate_effect)]
Precondition = Annotated[str, AfterValidator(_validate_precondition)]
TargetSelector = Annotated[str, AfterValidator(_validate_selector)]


class ScenarioEntry(BaseModel):
    """Where the attacker starts: a named asset or the first asset of a zone."""

    zone: Zone | None = None
    asset_code: Code | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> "ScenarioEntry":
        if (self.zone is None) == (self.asset_code is None):
            raise ValueError("entry needs exactly one of zone or asset_code")
        return self


class ScenarioGoal(BaseModel):
    """What counts as the attacker winning."""

    kind: GoalKind
    target_code: Code | None = None
    min_criticality: CriticalityLevel | None = None

    @model_validator(mode="after")
    def _fields_fit_kind(self) -> "ScenarioGoal":
        if self.kind == GoalKind.REACH_ASSET and self.target_code is None:
            raise ValueError("reach_asset goal needs target_code")
        if self.kind in (GoalKind.REACH_ANY_CRITICAL, GoalKind.ENCRYPT) and self.min_criticality is None:
            raise ValueError(f"{self.kind.value} goal needs min_criticality")
        return self


class ScenarioStep(BaseModel):
    """One step of an attack chain.

    A step targets either `target_code` or a `target_selector` resolved at run time.
    `advance` says whether the attacker moves to the target on success. `bypasses`
    lists connectivity control types the step is not subject to.
    """

    order: int = Field(ge=1)
    name: Name
    technique_id: str
    tactic: Tactic
    layer: int = Field(ge=2, le=7)
    protocol: Protocol = Protocol.ANY
    port: PortNumber | None = None
    service: str | None = None
    target_code: Code | None = None
    target_selector: TargetSelector | None = None
    preconditions: list[Precondition] = Field(default_factory=list)
    on_success: list[Effect] = Field(default_factory=list)
    advance: bool = True
    bypasses: list[ControlType] = Field(default_factory=list)
    bypass_reason: str | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _check(self) -> "ScenarioStep":
        if (self.target_code is None) == (self.target_selector is None):
            raise ValueError("step needs exactly one of target_code or target_selector")
        if not set(self.bypasses) <= _CONNECTIVITY_TYPES:
            raise ValueError("bypasses may only list firewall and segmentation")
        if self.bypasses and not self.bypass_reason:
            raise ValueError("bypass_reason is required when bypasses is set")
        return self


class Scenario(BaseModel):
    """A named attack chain with an entry point and a goal."""

    id: str
    code: Code
    name: Name
    description: str
    attacker_profile: AttackerProfile
    entry: ScenarioEntry
    goal: ScenarioGoal
    initial_effects: list[Precondition] = Field(default_factory=list)
    steps: list[ScenarioStep] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _steps_are_numbered_in_order(self) -> "Scenario":
        orders = [step.order for step in self.steps]
        if orders != list(range(1, len(orders) + 1)):
            raise ValueError("steps must be ordered 1, 2, 3, ... with no gaps")
        return self
