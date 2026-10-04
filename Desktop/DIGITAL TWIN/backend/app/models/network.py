"""Network models: the top-level container of a digital twin."""

from pydantic import BaseModel, Field, model_validator

from app.models.common import Name, StoredModel, reject_nulls


class NetworkCreate(BaseModel):
    """Request body for creating a network."""

    name: Name
    description: str = ""


class NetworkUpdate(BaseModel):
    """Request body for updating a network. Only sent fields change."""

    name: Name | None = None
    description: str | None = None

    @model_validator(mode="after")
    def _no_nulls(self) -> "NetworkUpdate":
        reject_nulls(self, frozenset())
        return self


class Network(StoredModel):
    """A stored network. `version` increments on every change to its assets, links or controls."""

    name: Name
    description: str = ""
    version: int = Field(default=1, ge=1)
    parent_network_id: str | None = None
    is_sandbox: bool = False


class NetworkRead(Network):
    """Response model for a network."""
