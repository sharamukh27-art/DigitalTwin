"""Attack graph models: pivot edges, attack paths, choke points and the best cut."""

from pydantic import BaseModel, Field

from app.models.enums import AssetType, Protocol, RemediationStatus, Zone


class PivotPort(BaseModel):
    """An open port on the target that traffic from the source is allowed to reach."""

    port: int
    protocol: Protocol
    service: str
    allowed_by: str | None = Field(
        default=None, description="Control that allowed the traffic. None means nothing filtered it."
    )
    rule_index: int | None = None


class PivotEdge(BaseModel):
    """From `source_code` an attacker can reach at least one open port on `target_code`."""

    source_code: str
    target_code: str
    ports: list[PivotPort]


class AttackPath(BaseModel):
    """A chain of hosts from an entry to a critical asset, each hop a pivot edge."""

    asset_codes: list[str]
    hops: int
    entry_code: str
    target_code: str
    target_criticality: int


class ChokePoint(BaseModel):
    """A host that attack paths pass through on their way to a target."""

    asset_id: str
    asset_code: str
    zone: Zone
    type: AssetType
    criticality: int
    paths_through: int
    percent: float
    betweenness: float
    is_target: bool


class ChokeFlow(BaseModel):
    """A pivot edge that attack paths use."""

    source_code: str
    target_code: str
    ports: list[PivotPort]
    paths_through: int
    percent: float


class RelatedRemediation(BaseModel):
    """An open remediation that acts on the best-cut host."""

    id: str
    title: str
    status: RemediationStatus


class BestCut(BaseModel):
    """The single host and the single flow whose removal blocks the most attack paths."""

    host: ChokePoint | None = None
    flow: ChokeFlow | None = None
    host_suggestion: str | None = None
    flow_suggestion: str | None = None
    related_remediations: list[RelatedRemediation] = Field(default_factory=list)


class AttackGraphResponse(BaseModel):
    """Reachability-based attack graph of a network."""

    network_id: str
    network_version: int
    min_criticality: int
    max_hops: int
    entries: list[str]
    targets: list[str]
    reachable_targets: list[str]
    pivot_edge_count: int
    edges: list[PivotEdge]
    total_paths: int
    truncated: bool
    paths: list[AttackPath]
    choke_points: list[ChokePoint]
    choke_flows: list[ChokeFlow]
    best_cut: BestCut
