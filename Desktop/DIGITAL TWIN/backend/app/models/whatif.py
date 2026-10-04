"""What-if models: twin patches and before/after comparison."""

from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.models.analysis import Posture
from app.models.common import Code
from app.models.enums import FinalOutcome, PatchTarget, RiskBand, StepOutcome
from app.models.run import DEFAULT_SEED


class PatchOp(BaseModel):
    """Change one control or asset, addressed by code.

    `set` maps dotted paths to new values, for example
    {"config.dynamic_arp_inspection": true} or {"config.rules.0.action": "deny"}.
    `append` and `prepend` map dotted paths of lists to one value to add at the end or
    the front; a value already in the list is left alone, so ops combine safely.
    `create` holds a new control: name, type, config and a placement that names assets
    by code. For controls, "placement.asset_codes" takes asset codes instead of ids.
    Within one op, set is applied first, then append, then prepend.
    """

    target: PatchTarget
    code: Code
    set: dict[str, Any] = Field(default_factory=dict)
    append: dict[str, Any] = Field(default_factory=dict)
    prepend: dict[str, Any] = Field(default_factory=dict)
    create: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _has_something_to_do(self) -> "PatchOp":
        changes = bool(self.set or self.append or self.prepend)
        if self.create is None and not changes:
            raise ValueError("a patch op needs at least one of set, append, prepend or create")
        if self.create is not None and changes:
            raise ValueError("create cannot be combined with set, append or prepend")
        if self.create is not None and self.target != PatchTarget.CONTROL:
            raise ValueError("create is only supported for controls")
        return self


class WhatIfRequest(BaseModel):
    """Body of POST /networks/{id}/whatif. `scenario_ids` may hold ids or codes; empty means all."""

    patch: list[PatchOp] = Field(min_length=1)
    scenario_ids: list[str] | None = None
    seed: int = DEFAULT_SEED


class WhatIfScenarioState(BaseModel):
    """One scenario's result on one side of the comparison."""

    scenario_code: str
    run_id: str
    risk_score: int
    band: RiskBand
    containment: FinalOutcome


class WhatIfSide(BaseModel):
    """The twin's results before or after the patch."""

    per_scenario: list[WhatIfScenarioState]
    posture: Posture


class StepChange(BaseModel):
    """A step whose outcome differs. None means the step was not executed on that side."""

    step_order: int
    from_outcome: StepOutcome | None = None
    to_outcome: StepOutcome | None = None


class WhatIfDiff(BaseModel):
    """Before/after difference of one scenario."""

    scenario_code: str
    risk_before: int
    risk_after: int
    delta: int
    containment_before: FinalOutcome
    containment_after: FinalOutcome
    steps_changed: list[StepChange]


class WhatIfSummary(BaseModel):
    """Totals across the compared scenarios. Negative delta means less risk."""

    total_risk_delta: int
    scenarios_improved: int
    scenarios_worsened: int
    scenarios_unchanged: int


class WhatIfResult(BaseModel):
    """Response of a what-if comparison."""

    network_id: str
    seed: int
    patch: list[PatchOp]
    before: WhatIfSide
    after: WhatIfSide
    diff: list[WhatIfDiff]
    summary: WhatIfSummary
    sandbox_id: str | None = Field(default=None, description="Set only when the sandbox was kept.")
