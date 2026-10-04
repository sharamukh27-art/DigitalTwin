"""Graph and paths endpoints."""

from httpx import AsyncClient

from tests.conftest import API, create_network


async def test_graph_shape(client: AsyncClient, acme_id: str, acme_codes: dict[str, str]) -> None:
    response = await client.get(f"{API}/networks/{acme_id}/graph")
    assert response.status_code == 200
    body = response.json()

    assert len(body["nodes"]) == 25
    assert len(body["edges"]) == 24
    node = next(item for item in body["nodes"] if item["data"]["code"] == "DB-01")
    assert node["id"] == acme_codes["DB-01"]
    assert node["type"] == "asset"
    assert set(node["position"]) == {"x", "y"}
    assert node["data"]["zone"] == "server"

    edge = next(item for item in body["edges"] if item["data"]["code"] == "L-24")
    assert edge["id"] == edge["data"]["id"]
    assert (edge["source"], edge["target"]) == (acme_codes["GUEST-DEV"], acme_codes["AP-01"])
    assert edge["data"]["type"] == "wifi"


async def test_graph_layout_puts_zones_in_trust_ordered_blocks(
    client: AsyncClient, acme_id: str
) -> None:
    first = (await client.get(f"{API}/networks/{acme_id}/graph")).json()
    second = (await client.get(f"{API}/networks/{acme_id}/graph")).json()
    assert first == second

    assert [group["zone"] for group in first["zones"]] == [
        "internet",
        "guest",
        "dmz",
        "corporate",
        "server",
        "management",
    ]
    assert sum(len(group["asset_ids"]) for group in first["zones"]) == 25

    spans: dict[str, list[float]] = {}
    for node in first["nodes"]:
        spans.setdefault(node["data"]["zone"], []).append(node["position"]["x"])
    ordered = [(min(spans[group["zone"]]), max(spans[group["zone"]])) for group in first["zones"]]
    assert all(left_max < right_min for (_, left_max), (right_min, _) in zip(ordered, ordered[1:]))
    assert len({x for x in spans["corporate"]}) == 3
    assert all(len({x for x in spans[zone]}) == 1 for zone in ("internet", "guest", "dmz", "server", "management"))
    assert max(node["position"]["y"] for node in first["nodes"]) == 440.0

    positions = {(node["position"]["x"], node["position"]["y"]) for node in first["nodes"]}
    assert len(positions) == 25


async def test_graph_of_empty_and_unknown_network(client: AsyncClient) -> None:
    network = await create_network(client)
    response = await client.get(f"{API}/networks/{network['id']}/graph")
    assert response.json() == {"nodes": [], "edges": [], "zones": []}
    assert (await client.get(f"{API}/networks/missing/graph")).status_code == 404


async def test_paths_from_guest_to_database(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    response = await client.get(
        f"{API}/networks/{acme_id}/paths",
        params={"from": acme_codes["GUEST-DEV"], "to": acme_codes["DB-01"]},
    )
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert len(paths) >= 1
    path = paths[0]
    assert path["asset_ids"] == [
        acme_codes[code] for code in ("GUEST-DEV", "AP-01", "SW-ACCESS-2", "SW-CORE", "DB-01")
    ]
    assert path["hops"] == 4
    assert len(path["link_ids"]) == 4
    assert path["zone_crossings"] == [
        {"from_zone": "guest", "to_zone": "corporate"},
        {"from_zone": "corporate", "to_zone": "management"},
        {"from_zone": "management", "to_zone": "server"},
    ]


async def test_paths_respect_max_hops(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    response = await client.get(
        f"{API}/networks/{acme_id}/paths",
        params={"from": acme_codes["GUEST-DEV"], "to": acme_codes["DB-01"], "max_hops": 3},
    )
    assert response.status_code == 200
    assert response.json() == {"paths": []}


async def test_paths_follow_graph_changes(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    params = {"from": acme_codes["GUEST-DEV"], "to": acme_codes["DB-01"]}
    url = f"{API}/networks/{acme_id}/paths"
    assert len((await client.get(url, params=params)).json()["paths"]) == 1

    deleted = await client.delete(f"{API}/networks/{acme_id}/assets/{acme_codes['AP-01']}")
    assert deleted.status_code == 204
    assert (await client.get(url, params=params)).json() == {"paths": []}


async def test_paths_errors(client: AsyncClient, acme_id: str, acme_codes: dict[str, str]) -> None:
    url = f"{API}/networks/{acme_id}/paths"
    known = acme_codes["DB-01"]

    assert (await client.get(url, params={"from": "missing", "to": known})).status_code == 404
    assert (await client.get(url, params={"from": known, "to": "missing"})).status_code == 404
    assert (await client.get(url, params={"from": known})).status_code == 422
    assert (await client.get(url, params={"from": known, "to": known})).status_code == 422
    assert (
        await client.get(url, params={"from": known, "to": acme_codes["WS-01"], "max_hops": 0})
    ).status_code == 422
    assert (
        await client.get(f"{API}/networks/missing/paths", params={"from": "a", "to": "b"})
    ).status_code == 404
