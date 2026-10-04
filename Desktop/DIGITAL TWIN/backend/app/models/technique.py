"""Model for one entry of the ATT&CK technique catalog."""

from pydantic import BaseModel, Field

from app.models.enums import Tactic


class Technique(BaseModel):
    """An ATT&CK technique as listed in data/attack/techniques.yaml."""

    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1)
    tactic: Tactic
    osi_layer: int = Field(ge=2, le=7)
    description: str = Field(min_length=1)
