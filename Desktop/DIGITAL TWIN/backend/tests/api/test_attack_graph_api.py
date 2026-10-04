"""Attack graph endpoint."""

import pytest
from httpx import AsyncClient

from app.analysis import attack_graph
from tests.conftest import API, create_network


@pytest.fixture(autouse=True)
def fresh_cache() -> None:
    attack_graph.clear_cache()


async def test_attack_graph(client: AsyncClient, acme_id: str) -> None:
    response = await client.get(f"{API}/networks/{acme_id}/attack-graph")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "network_id", "network_version", "min_criticality", "max_hops", "entries", "targets",
        "reachable_targets", "pivot_edge_count", "edges", "total_paths", "truncated", "paths",
        "choke_points", "choke_flows", "best_cut",
    }
    assert (body["total_paths"], body["entries"]) == (223, ["GUEST-DEV", "INTERNET"])
    assert set(body["choke_points"][0]) == {
        "asset_id", "asset_code", "zone", "type", "criticality", "paths_through", "percent", "betweenness", "is_target",
    }
    assert body["choke_points"][0]["asset_code"] == "SW-ACCESS-2"
    assert set(body["best_cut"]) == {"host", "flow", "host_suggestion", "flow_suggestion", "related_remediations"}
    assert body["best_cut"]["flow"]["ports"][0]["allowed_by"] == "SEG-01"
    assert len(body["choke_points"]) <= 15 and len(body["choke_flows"]) <= 15 and len(body["paths"]) == 50
    used = {(edge["source_code"], edge["target_code"]) for edge in body["edges"]}
    assert ("INTERNET", "WEB-01") in used and ("WEB-01", "APP-01") in used

    narrow = (await client.get(f"{API}/networks/{acme_id}/attack-graph", params={"min_criticality": 5, "max_hops": 2})).json()
    assert (narrow["targets"], narrow["max_hops"]) == (["DB-01", "DC-01"], 2)
    assert all(path["hops"] <= 2 for path in narrow["paths"])


async def test_attack_graph_errors_and_empty_network(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/attack-graph"
    for params in ({"min_criticality": 0}, {"min_criticality": 6}, {"max_hops": 0}, {"max_hops": 7}):
        assert (await client.get(url, params=params)).status_code == 422
    assert (await client.get(f"{API}/networks/missing/attack-graph")).status_code == 404

    empty = await create_network(client, "empty")
    body = (await client.get(f"{API}/networks/{empty['id']}/attack-graph")).json()
    assert (body["entries"], body["targets"], body["total_paths"], body["paths"]) == ([], [], 0, [])
    assert body["best_cut"]["host"] is None
