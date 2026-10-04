"""Graph construction, caching, paths and zone queries."""

from typing import Any

import pytest

from app.core.errors import NotFound
from app.models.asset import Asset
from app.models.enums import Zone
from app.models.link import Link
from app.twin import graph as twin_graph
from app.twin import repository
from app.twin.versioning import bump_version


def codes(graph: Any, asset_ids: Any) -> list[str]:
    return [graph.nodes[asset_id]["code"] for asset_id in asset_ids]


def make_asset(code: str, zone: str = "server") -> Asset:
    return Asset(id=code, network_id="n", code=code, name=code, type="server", zone=zone)


def make_link(code: str, source: str, target: str, bidirectional: bool = True) -> Link:
    return Link(
        id=code,
        network_id="n",
        code=code,
        source_asset_id=source,
        target_asset_id=target,
        type="ethernet",
        bidirectional=bidirectional,
    )


async def test_graph_has_node_and_edge_attributes(acme_id: str, acme_codes: dict[str, str]) -> None:
    graph = await twin_graph.build_graph(acme_id)
    assert graph.number_of_nodes() == 25
    assert graph.number_of_edges() == 48
    node = graph.nodes[acme_codes["DB-01"]]
    assert node["code"] == "DB-01"
    assert node["criticality"] == 5
    assert node["data_classification"] == "restricted"
    edge = graph[acme_codes["GUEST-DEV"]][acme_codes["AP-01"]]
    assert [data["type"] for data in edge.values()] == ["wifi"]


def test_one_way_link_creates_a_single_edge() -> None:
    graph = twin_graph.graph_from_models(
        [make_asset("A"), make_asset("B")], [make_link("L1", "A", "B", bidirectional=False)]
    )
    assert graph.has_edge("A", "B")
    assert not graph.has_edge("B", "A")
    assert twin_graph.shortest_path(graph, "B", "A") is None
    assert twin_graph.reachable_from(graph, "B") == set()
    assert twin_graph.reachable_from(graph, "A") == {"B"}


async def test_graph_is_cached_per_version(acme_id: str) -> None:
    first = await twin_graph.build_graph(acme_id)
    assert await twin_graph.build_graph(acme_id) is first
    await bump_version(acme_id)
    rebuilt = await twin_graph.build_graph(acme_id)
    assert rebuilt is not first
    assert rebuilt.graph["version"] == 2


async def test_build_graph_unknown_network_raises_not_found(database: Any) -> None:
    with pytest.raises(NotFound):
        await twin_graph.build_graph("missing")


async def test_neighbors(acme_id: str, acme_codes: dict[str, str]) -> None:
    graph = await twin_graph.build_graph(acme_id)
    assert codes(graph, twin_graph.neighbors(graph, acme_codes["FW-EDGE"])) == [
        "FW-INT",
        "INTERNET",
        "VPN-01",
        "WEB-01",
    ]


async def test_guest_to_database_path_and_zone_crossings(
    acme_id: str, acme_codes: dict[str, str]
) -> None:
    graph = await twin_graph.build_graph(acme_id)
    paths = twin_graph.all_paths(graph, acme_codes["GUEST-DEV"], acme_codes["DB-01"])
    assert len(paths) == 1
    path = paths[0]
    assert codes(graph, path.asset_ids) == ["GUEST-DEV", "AP-01", "SW-ACCESS-2", "SW-CORE", "DB-01"]
    assert path.hops == 4
    assert len(path.link_ids) == 4
    assert twin_graph.zone_crossings(graph, path.asset_ids) == [
        (Zone.GUEST, Zone.CORPORATE),
        (Zone.CORPORATE, Zone.MANAGEMENT),
        (Zone.MANAGEMENT, Zone.SERVER),
    ]


async def test_max_hops_limits_paths(acme_id: str, acme_codes: dict[str, str]) -> None:
    graph = await twin_graph.build_graph(acme_id)
    source, target = acme_codes["GUEST-DEV"], acme_codes["DB-01"]
    assert twin_graph.all_paths(graph, source, target, max_hops=3) == []
    assert len(twin_graph.all_paths(graph, source, target, max_hops=4)) == 1


def test_all_paths_are_shortest_first_and_respect_limit() -> None:
    assets = [make_asset(code) for code in ("A", "B", "C", "D")]
    links = [
        make_link("L1", "A", "B"),
        make_link("L2", "B", "D"),
        make_link("L3", "A", "D"),
        make_link("L4", "A", "C"),
        make_link("L5", "C", "D"),
        make_link("L6", "A", "D"),
    ]
    graph = twin_graph.graph_from_models(assets, links)
    paths = twin_graph.all_paths(graph, "A", "D")
    assert [(path.asset_ids, path.link_ids) for path in paths] == [
        (["A", "D"], ["L3"]),
        (["A", "D"], ["L6"]),
        (["A", "B", "D"], ["L1", "L2"]),
        (["A", "C", "D"], ["L4", "L5"]),
    ]
    assert [path.hops for path in twin_graph.all_paths(graph, "A", "D", limit=2)] == [1, 1]
    assert twin_graph.all_paths(graph, "A", "A") == []


async def test_shortest_path(acme_id: str, acme_codes: dict[str, str]) -> None:
    graph = await twin_graph.build_graph(acme_id)
    path = twin_graph.shortest_path(graph, acme_codes["INTERNET"], acme_codes["DC-01"])
    assert path is not None
    assert codes(graph, path.asset_ids) == ["INTERNET", "FW-EDGE", "FW-INT", "SW-CORE", "DC-01"]
    assert path.hops == 4


async def test_reachable_from(acme_id: str, acme_codes: dict[str, str]) -> None:
    graph = await twin_graph.build_graph(acme_id)
    reachable = twin_graph.reachable_from(graph, acme_codes["GUEST-DEV"])
    assert len(reachable) == 24
    assert acme_codes["GUEST-DEV"] not in reachable


async def test_assets_in_zone(acme_id: str) -> None:
    graph = await twin_graph.build_graph(acme_id)
    assert codes(graph, twin_graph.assets_in_zone(graph, Zone.DMZ)) == ["FW-EDGE", "VPN-01", "WEB-01"]
    assert codes(graph, twin_graph.assets_in_zone(graph, "server")) == [
        "APP-01",
        "DB-01",
        "DC-01",
        "FS-01",
    ]
    assert len(twin_graph.assets_in_zone(graph, Zone.CORPORATE)) == 13


def test_zone_crossings_ignores_steps_inside_a_zone() -> None:
    graph = twin_graph.graph_from_models(
        [make_asset("A", "dmz"), make_asset("B", "dmz"), make_asset("C", "server")],
        [make_link("L1", "A", "B"), make_link("L2", "B", "C")],
    )
    assert twin_graph.zone_crossings(graph, ["A", "B"]) == []
    assert twin_graph.zone_crossings(graph, ["A", "B", "C"]) == [(Zone.DMZ, Zone.SERVER)]
    assert twin_graph.zone_crossings(graph, []) == []


async def test_unknown_ids_raise_not_found(acme_id: str, acme_codes: dict[str, str]) -> None:
    graph = await twin_graph.build_graph(acme_id)
    known = acme_codes["DB-01"]
    with pytest.raises(NotFound):
        twin_graph.neighbors(graph, "missing")
    with pytest.raises(NotFound):
        twin_graph.all_paths(graph, "missing", known)
    with pytest.raises(NotFound):
        twin_graph.all_paths(graph, known, "missing")
    with pytest.raises(NotFound):
        twin_graph.shortest_path(graph, known, "missing")
    with pytest.raises(NotFound):
        twin_graph.reachable_from(graph, "missing")
    with pytest.raises(NotFound):
        twin_graph.zone_crossings(graph, [known, "missing"])


async def test_deleting_an_asset_removes_it_from_the_next_graph(
    acme_id: str, acme_codes: dict[str, str]
) -> None:
    await repository.delete_asset(acme_id, acme_codes["AP-01"])
    await bump_version(acme_id)
    graph = await twin_graph.build_graph(acme_id)
    assert acme_codes["AP-01"] not in graph
    assert twin_graph.all_paths(graph, acme_codes["GUEST-DEV"], acme_codes["DB-01"]) == []
