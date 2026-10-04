"""In-memory NetworkX graph of a twin, plus path and zone queries.

The graph is pure data built from MongoDB. Nothing here touches a real network.
"""

from collections.abc import Sequence

import networkx as nx

from app.core.errors import NotFound
from app.models.asset import Asset
from app.models.enums import Zone
from app.models.link import Link
from app.models.twin_io import GraphPath
from app.twin import repository

_CACHE: dict[tuple[str, int], nx.MultiDiGraph] = {}


def clear_cache() -> None:
    """Drop every cached graph."""
    _CACHE.clear()


def evict(network_id: str) -> None:
    """Drop the cached graphs of one network, for example after it was deleted."""
    for stale in [key for key in _CACHE if key[0] == network_id]:
        del _CACHE[stale]


def graph_from_models(assets: Sequence[Asset], links: Sequence[Link]) -> nx.MultiDiGraph:
    """Build a graph from assets and links.

    Nodes are keyed by asset id with the asset fields as attributes. Edges are keyed
    by link id with the link fields as attributes. A bidirectional link adds a second
    edge in the opposite direction, marked with direction="reverse".
    """
    graph = nx.MultiDiGraph()
    for asset in assets:
        graph.add_node(asset.id, **asset.model_dump(mode="json"))
    for link in links:
        attributes = link.model_dump(mode="json")
        graph.add_edge(
            link.source_asset_id, link.target_asset_id, key=link.id, direction="forward", **attributes
        )
        if link.bidirectional:
            graph.add_edge(
                link.target_asset_id,
                link.source_asset_id,
                key=link.id,
                direction="reverse",
                **attributes,
            )
    return graph


async def build_graph(network_id: str) -> nx.MultiDiGraph:
    """Return the graph of a network, cached by (network_id, version).

    The returned graph is shared between callers and must be treated as read-only.
    Raises NotFound for unknown network ids.
    """
    network = await repository.get_network(network_id)
    key = (network.id, network.version)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    assets = await repository.all_assets(network_id)
    links = await repository.all_links(network_id)
    graph = graph_from_models(assets, links)
    graph.graph["network_id"] = network.id
    graph.graph["version"] = network.version
    for stale in [cached_key for cached_key in _CACHE if cached_key[0] == network.id]:
        del _CACHE[stale]
    _CACHE[key] = graph
    return graph


def _require(graph: nx.MultiDiGraph, asset_id: str) -> None:
    """Raise NotFound when the asset is not a node of the graph."""
    if asset_id not in graph:
        raise NotFound(f"Asset {asset_id} not found in the network graph", {"asset_id": asset_id})


def _node_codes(graph: nx.MultiDiGraph, asset_ids: Sequence[str]) -> list[str]:
    return [graph.nodes[asset_id]["code"] for asset_id in asset_ids]


def neighbors(graph: nx.MultiDiGraph, asset_id: str) -> list[str]:
    """Return the ids of assets directly reachable from an asset, ordered by code."""
    _require(graph, asset_id)
    return sorted(graph.successors(asset_id), key=lambda node: graph.nodes[node]["code"])


def all_paths(
    graph: nx.MultiDiGraph, src: str, dst: str, max_hops: int = 6, limit: int = 50
) -> list[GraphPath]:
    """Return simple paths from src to dst with at most max_hops links, shortest first.

    Parallel links between the same two assets produce separate paths. Ties are
    ordered by asset codes, then link codes, so the result is deterministic.
    """
    _require(graph, src)
    _require(graph, dst)
    if src == dst or max_hops < 1 or limit < 1:
        return []
    found: list[tuple[tuple[int, list[str], list[str]], GraphPath]] = []
    for edge_path in nx.all_simple_edge_paths(graph, src, dst, cutoff=max_hops):
        asset_ids = [edge_path[0][0], *(edge[1] for edge in edge_path)]
        link_ids = [edge[2] for edge in edge_path]
        link_codes = [graph.edges[edge]["code"] for edge in edge_path]
        path = GraphPath(asset_ids=asset_ids, link_ids=link_ids, hops=len(link_ids))
        found.append(((path.hops, _node_codes(graph, asset_ids), link_codes), path))
    found.sort(key=lambda item: item[0])
    return [path for _, path in found[:limit]]


def shortest_path(graph: nx.MultiDiGraph, src: str, dst: str) -> GraphPath | None:
    """Return a path with the fewest hops from src to dst, or None when unreachable."""
    _require(graph, src)
    _require(graph, dst)
    try:
        asset_ids: list[str] = nx.shortest_path(graph, src, dst)
    except nx.NetworkXNoPath:
        return None
    link_ids: list[str] = []
    for source, target in zip(asset_ids, asset_ids[1:]):
        parallel = graph[source][target]
        link_ids.append(min(parallel, key=lambda link_id: parallel[link_id]["code"]))
    return GraphPath(asset_ids=asset_ids, link_ids=link_ids, hops=len(link_ids))


def reachable_from(graph: nx.MultiDiGraph, asset_id: str) -> set[str]:
    """Return the ids of every asset reachable from an asset, excluding itself."""
    _require(graph, asset_id)
    return set(nx.descendants(graph, asset_id))


def assets_in_zone(graph: nx.MultiDiGraph, zone: Zone | str) -> list[str]:
    """Return the ids of the assets in a zone, ordered by code."""
    wanted = Zone(zone).value
    members = [node for node, data in graph.nodes(data=True) if data["zone"] == wanted]
    return sorted(members, key=lambda node: graph.nodes[node]["code"])


def zone_crossings(graph: nx.MultiDiGraph, path: Sequence[str]) -> list[tuple[Zone, Zone]]:
    """Return (from_zone, to_zone) for each step of a path that changes zone."""
    for asset_id in path:
        _require(graph, asset_id)
    crossings: list[tuple[Zone, Zone]] = []
    for source, target in zip(path, path[1:]):
        from_zone = Zone(graph.nodes[source]["zone"])
        to_zone = Zone(graph.nodes[target]["zone"])
        if from_zone != to_zone:
            crossings.append((from_zone, to_zone))
    return crossings
