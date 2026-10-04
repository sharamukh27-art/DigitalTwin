"""Link models: connections between two assets of the same network."""

from pydantic import BaseModel, Field, model_validator

from app.models.common import Code, PortNumber, StoredModel, reject_nulls
from app.models.enums import LinkType, Protocol


def _default_protocols() -> list[Protocol]:
    return [Protocol.ANY]


class LinkAttributes(BaseModel):
    """Link fields that do not reference assets. Shared by the API and the import file."""

    code: Code
    type: LinkType
    allowed_protocols: list[Protocol] = Field(default_factory=_default_protocols)
    allowed_ports: list[PortNumber] = Field(
        default_factory=list, description="Ports allowed across the link. Empty means all."
    )
    bidirectional: bool = True


class LinkBase(LinkAttributes):
    """Fields a client supplies for a link."""

    source_asset_id: str
    target_asset_id: str

    @model_validator(mode="after")
    def _no_self_link(self) -> "LinkBase":
        if self.source_asset_id == self.target_asset_id:
            raise ValueError("a link cannot connect an asset to itself")
        return self


class LinkCreate(LinkBase):
    """Request body for creating a link."""


class LinkUpdate(BaseModel):
    """Request body for updating a link. Only sent fields change."""

    code: Code | None = None
    source_asset_id: str | None = None
    target_asset_id: str | None = None
    type: LinkType | None = None
    allowed_protocols: list[Protocol] | None = None
    allowed_ports: list[PortNumber] | None = None
    bidirectional: bool | None = None

    @model_validator(mode="after")
    def _no_nulls(self) -> "LinkUpdate":
        reject_nulls(self, frozenset())
        return self


class Link(LinkBase, StoredModel):
    """A stored link."""

    network_id: str


class LinkRead(Link):
    """Response model for a link."""
