"""Attack graph analysis: which chains of hosts lead from outside to critical assets.

Pure logic over twin data. Nothing here sends packets or contacts a real host.

An edge A -> B in the pivot graph means that traffic from A is allowed to reach at
least one open port on B, as decided by the firewall and segmentation controls. It
says an attacker on A could try B; it does not say an exploit or credential exists.
"""

from collections import Counter
from collections.abc import Sequence

import networkx as nx

from app.controls import repository as control_repository
from app.controls.connectivity import check_flow
from app.models.asset import Asset
from app.models.attack_graph import (
    AttackGraphResponse,
    AttackPath,
    BestCut,
    ChokeFlow,
    ChokePoint,
    PivotEdge,
    PivotPort,
    RelatedRemediation,
)
from app.models.control import SecurityControl
from app.models.enums import RemediationStatus, Zone
from app.remediation import repository as remediation_repository
from app.simulation.targeting import is_host
from app.twin import graph as twin_graph
from app.twin import repository as twin_repository

ENTRY_ZONES = (Zone.INTERNET, Zone.GUEST)
PATHS_RETURNED = 50
CHOKE_ITEMS_RETURNED = 15
PATH_CAP = 50_000
_OPEN = (RemediationStatus.PROPOSED, RemediationStatus.VERIFIED)

_CACHE: dict[tuple[str, int, int, int], AttackGraphResponse] = {}


def clear_cache() -> None:
    """Drop every cached attack graph."""
    _CACHE.clear()


def build_pivot_graph(
    assets: Sequence[Asset], controls: Sequence[SecurityControl], topology: nx.MultiDiGraph
) -> nx.DiGraph:
    """Build the pivot graph: an edge A -> B when A can reach an open port on B.

    For every ordered pair of assets with a cable path between them, each open port
    of B is checked with the connectivity rules along the shortest cable path. The
    edge stores the reachable ports and which control allowed each. Nodes are asset ids.
    """
    by_id = {asset.id: asset for asset in assets}
    control_codes = {control.id: control.code for control in controls}
    pivot = nx.DiGraph()
    pivot.add_nodes_from(by_id)
    for source in sorted(assets, key=lambda asset: asset.code):
        routes = nx.single_source_shortest_path(topology, source.id) if source.id in topology else {}
        for target in sorted(assets, key=lambda asset: asset.code):
            if target.id == source.id or not target.open_ports or target.id not in routes:
                continue
            reachable: list[PivotPort] = []
            for port in target.open_ports:
                decision = check_flow(controls, source, target, routes[target.id], port.protocol, port.port)
                if decision.allowed:
                    reachable.append(
                        PivotPort(
                            port=port.port,
                            protocol=port.protocol,
                            service=port.service,
                            allowed_by=control_codes.get(decision.deciding_control_id or ""),
                            rule_index=decision.rule_index,
                        )
                    )
            if reachable:
                pivot.add_edge(source.id, target.id, ports=reachable)
    return pivot


def _host_suggestion(host: ChokePoint) -> str:
    """Say what hardening the top choke host would achieve."""
    return (
        f"{host.paths_through} of the attack paths ({host.percent}%) pass through {host.asset_code}. "
        f"Hardening or isolating it blocks them."
    )


def _flow_suggestion(flow: ChokeFlow) -> str:
    """Say which allowed flow to close, and which control currently lets it through."""
    ports = ", ".join(str(port.port) for port in flow.ports)
    deciders = []
    for port in flow.ports:
        if port.allowed_by is None:
            decider = "nothing filters it"
        elif port.rule_index is None:
            decider = f"the default action of {port.allowed_by} allows it"
        else:
            decider = f"{port.allowed_by} rule {port.rule_index} allows it"
        if decider not in deciders:
            deciders.append(decider)
    return (
        f"{flow.paths_through} of the attack paths ({flow.percent}%) use {flow.source_code} -> "
        f"{flow.target_code} on port {ports}; {' and '.join(deciders)}. Blocking that flow cuts them."
    )


def build_attack_graph(
    network_id: str,
    network_version: int,
    assets: Sequence[Asset],
    controls: Sequence[SecurityControl],
    topology: nx.MultiDiGraph,
    min_criticality: int = 4,
    max_hops: int = 4,
) -> AttackGraphResponse:
    """Compute attack paths and choke points from twin data already in memory. Pure.

    Entries are the assets in the internet and guest zones. Targets are hosts at or
    above `min_criticality` outside those zones. Attack paths are all simple paths in
    the pivot graph from an entry to a target with at most `max_hops` hops.

    A choke point is a host in the middle of attack paths, ranked by how many pass
    through it (ties: betweenness, then code). Choke flows rank pivot edges the same
    way. `best_cut` names the top host and top flow. Enumeration stops at 50,000 paths
    and sets `truncated`.
    """
    by_id = {asset.id: asset for asset in assets}
    entries = sorted((a for a in assets if a.zone in ENTRY_ZONES), key=lambda asset: asset.code)
    targets = sorted(
        (a for a in assets if is_host(a) and a.criticality >= min_criticality and a.zone not in ENTRY_ZONES),
        key=lambda asset: asset.code,
    )
    pivot = build_pivot_graph(assets, controls, topology)

    found: list[tuple[str, ...]] = []
    node_counts: Counter[str] = Counter()
    edge_counts: Counter[tuple[str, str]] = Counter()
    truncated = False
    for entry in entries:
        for target in targets:
            if truncated:
                break
            for path in nx.all_simple_paths(pivot, entry.id, target.id, cutoff=max_hops):
                if len(found) >= PATH_CAP:
                    truncated = True
                    break
                found.append(tuple(path))
                node_counts.update(path[1:-1])
                edge_counts.update(zip(path, path[1:]))
    total = len(found)

    def share(count: int) -> float:
        return round(100 * count / total, 1) if total else 0.0

    betweenness = (
        nx.betweenness_centrality_subset(
            pivot, [entry.id for entry in entries], [target.id for target in targets], normalized=False
        )
        if entries and targets
        else {}
    )
    target_ids = {target.id for target in targets}
    choke_points = sorted(
        (
            ChokePoint(
                asset_id=asset_id,
                asset_code=by_id[asset_id].code,
                zone=by_id[asset_id].zone,
                type=by_id[asset_id].type,
                criticality=by_id[asset_id].criticality,
                paths_through=count,
                percent=share(count),
                betweenness=round(betweenness.get(asset_id, 0.0), 3),
                is_target=asset_id in target_ids,
            )
            for asset_id, count in node_counts.items()
        ),
        key=lambda item: (-item.paths_through, -item.betweenness, item.asset_code),
    )
    choke_flows = sorted(
        (
            ChokeFlow(
                source_code=by_id[source].code,
                target_code=by_id[target].code,
                ports=pivot.edges[source, target]["ports"],
                paths_through=count,
                percent=share(count),
            )
            for (source, target), count in edge_counts.items()
        ),
        key=lambda item: (-item.paths_through, item.source_code, item.target_code),
    )

    ordered = sorted(found, key=lambda path: (len(path), [by_id[node].code for node in path]))
    return AttackGraphResponse(
        network_id=network_id,
        network_version=network_version,
        min_criticality=min_criticality,
        max_hops=max_hops,
        entries=[entry.code for entry in entries],
        targets=[target.code for target in targets],
        reachable_targets=sorted({by_id[path[-1]].code for path in found}),
        pivot_edge_count=pivot.number_of_edges(),
        edges=sorted(
            (
                PivotEdge(source_code=by_id[s].code, target_code=by_id[t].code, ports=pivot.edges[s, t]["ports"])
                for s, t in edge_counts
            ),
            key=lambda edge: (edge.source_code, edge.target_code),
        ),
        total_paths=total,
        truncated=truncated,
        paths=[
            AttackPath(
                asset_codes=[by_id[node].code for node in path],
                hops=len(path) - 1,
                entry_code=by_id[path[0]].code,
                target_code=by_id[path[-1]].code,
                target_criticality=by_id[path[-1]].criticality,
            )
            for path in ordered[:PATHS_RETURNED]
        ],
        choke_points=choke_points[:CHOKE_ITEMS_RETURNED],
        choke_flows=choke_flows[:CHOKE_ITEMS_RETURNED],
        best_cut=BestCut(
            host=choke_points[0] if choke_points else None,
            flow=choke_flows[0] if choke_flows else None,
            host_suggestion=_host_suggestion(choke_points[0]) if choke_points else None,
            flow_suggestion=_flow_suggestion(choke_flows[0]) if choke_flows else None,
        ),
    )


async def _related_remediations(
    network_id: str, host: ChokePoint | None, controls: Sequence[SecurityControl]
) -> list[RelatedRemediation]:
    """Return open remediations whose control is placed on the best-cut host."""
    if host is None:
        return []
    on_host = {control.code for control in controls if host.asset_id in control.placement.asset_ids}
    return [
        RelatedRemediation(id=item.id, title=item.title, status=item.status)
        for item in await remediation_repository.list_remediations(network_id)
        if item.status in _OPEN and (item.target.code in on_host or host.asset_code in item.affected_assets)
    ]


async def attack_graph(network_id: str, min_criticality: int = 4, max_hops: int = 4) -> AttackGraphResponse:
    """Return the attack graph of a network, cached per network version and parameters.

    Raises NotFound for unknown network ids.
    """
    network = await twin_repository.get_network(network_id)
    controls = await control_repository.all_controls(network_id)
    key = (network.id, network.version, min_criticality, max_hops)
    if key not in _CACHE:
        for stale in [cached for cached in _CACHE if cached[0] == network.id and cached[1] != network.version]:
            del _CACHE[stale]
        _CACHE[key] = build_attack_graph(
            network.id,
            network.version,
            await twin_repository.all_assets(network_id),
            controls,
            await twin_graph.build_graph(network_id),
            min_criticality,
            max_hops,
        )
    result = _CACHE[key]
    related = await _related_remediations(network_id, result.best_cut.host, controls)
    return result.model_copy(
        update={"best_cut": result.best_cut.model_copy(update={"related_remediations": related})}
    )
