"""Models for twin import/export files and for graph and path responses."""

from typing import Literal

from pydantic import BaseModel, Field

from app.models.asset import AssetCreate, AssetRead
from app.models.common import Code
from app.models.control import ControlAttributes
from app.models.enums import ControlType, PlacementKind, Zone
from app.models.link import LinkAttributes, LinkRead
from app.models.network import NetworkCreate


class ImportLink(LinkAttributes):
    """A link inside an import/export file. Endpoints are asset codes, not ids."""

    source: Code
    target: Code


class ImportPlacement(BaseModel):
    """A control placement inside an import/export file. Assets are codes, not ids."""

    kind: PlacementKind
    asset_codes: list[Code] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


class ImportControl(ControlAttributes):
    """A security control inside an import/export file."""

    placement: ImportPlacement


class NetworkFile(BaseModel):
    """Shape of an import/export file."""

    network: NetworkCreate
    assets: list[AssetCreate] = Field(default_factory=list)
    links: list[ImportLink] = Field(default_factory=list)
    controls: list[ImportControl] = Field(default_factory=list)


class ImportResult(BaseModel):
    """Outcome of an import. When `errors` is not empty nothing was written."""

    network_id: str | None = None
    assets_created: int = 0
    links_created: int = 0
    controls_created: int = 0
    errors: list[str] = Field(default_factory=list)


class Position(BaseModel):
    """Canvas position of a graph node."""

    x: float
    y: float


class NodeControl(BaseModel):
    """A control that protects an asset, shown on its graph node."""

    code: str
    name: str
    type: ControlType
    kind: PlacementKind
    enabled: bool


class GraphNode(BaseModel):
    """A React Flow node representing an asset."""

    id: str
    type: Literal["asset"] = "asset"
    position: Position
    data: AssetRead
    controls: list[NodeControl] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """A React Flow edge representing a link."""

    id: str
    source: str
    target: str
    data: LinkRead


class ZoneGroup(BaseModel):
    """The assets that sit in one zone."""

    zone: Zone
    asset_ids: list[str]


class GraphResponse(BaseModel):
    """Response of GET /networks/{id}/graph."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    zones: list[ZoneGroup]


class GraphPath(BaseModel):
    """A path through the twin graph."""

    asset_ids: list[str]
    link_ids: list[str]
    hops: int


class ZoneCrossing(BaseModel):
    """One step of a path that moves between two different zones."""

    from_zone: Zone
    to_zone: Zone


class PathItem(GraphPath):
    """A path together with the zone boundaries it crosses."""

    zone_crossings: list[ZoneCrossing]


class PathsResponse(BaseModel):
    """Response of GET /networks/{id}/paths."""

    paths: list[PathItem]
