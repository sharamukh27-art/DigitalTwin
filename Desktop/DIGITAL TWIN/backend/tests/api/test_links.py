"""Link CRUD endpoints."""

from typing import Any

import pytest_asyncio
from httpx import AsyncClient

from tests.conftest import API, create_asset, create_network, network_version


@pytest_asyncio.fixture
async def pair(client: AsyncClient) -> dict[str, Any]:
    """A network with three assets and no links."""
    network = await create_network(client)
    assets = [await create_asset(client, network["id"], code=code) for code in ("A", "B", "C")]
    return {
        "network_id": network["id"],
        "a": assets[0]["id"],
        "b": assets[1]["id"],
        "c": assets[2]["id"],
        "url": f"{API}/networks/{network['id']}/links",
    }


def link_payload(source: str, target: str, code: str = "L-1", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "code": code,
        "source_asset_id": source,
        "target_asset_id": target,
        "type": "ethernet",
    }
    payload.update(overrides)
    return payload


async def test_create_link(client: AsyncClient, pair: dict[str, Any]) -> None:
    before = await network_version(client, pair["network_id"])
    response = await client.post(
        pair["url"],
        json=link_payload(pair["a"], pair["b"], allowed_protocols=["tcp"], allowed_ports=[443]),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["network_id"] == pair["network_id"]
    assert body["allowed_protocols"] == ["tcp"]
    assert body["allowed_ports"] == [443]
    assert body["bidirectional"] is True
    assert await network_version(client, pair["network_id"]) == before + 1


async def test_create_link_validation_is_422(client: AsyncClient, pair: dict[str, Any]) -> None:
    before = await network_version(client, pair["network_id"])
    for payload in (
        link_payload(pair["a"], pair["a"]),
        link_payload(pair["a"], "missing-asset"),
        link_payload(pair["a"], pair["b"], type="carrier-pigeon"),
        link_payload(pair["a"], pair["b"], allowed_ports=[0]),
        link_payload(pair["a"], pair["b"], allowed_protocols=["gre"]),
    ):
        response = await client.post(pair["url"], json=payload)
        assert response.status_code == 422, payload
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
    assert await network_version(client, pair["network_id"]) == before


async def test_link_to_asset_of_another_network_is_422(
    client: AsyncClient, pair: dict[str, Any]
) -> None:
    other = await create_network(client, "other")
    foreign = await create_asset(client, other["id"], code="X")
    response = await client.post(pair["url"], json=link_payload(pair["a"], foreign["id"]))
    assert response.status_code == 422
    assert response.json()["error"]["details"] == {"missing_asset_ids": [foreign["id"]]}


async def test_duplicate_link_code_is_409(client: AsyncClient, pair: dict[str, Any]) -> None:
    assert (await client.post(pair["url"], json=link_payload(pair["a"], pair["b"]))).status_code == 201
    response = await client.post(pair["url"], json=link_payload(pair["b"], pair["c"]))
    assert response.status_code == 409


async def test_create_link_in_unknown_network_is_404(client: AsyncClient) -> None:
    response = await client.post(f"{API}/networks/missing/links", json=link_payload("a", "b"))
    assert response.status_code == 404


async def test_list_and_get_links(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/links"
    listing = (await client.get(url, params={"limit": 5})).json()
    assert listing["total"] == 24
    assert [item["code"] for item in listing["items"]] == ["L-01", "L-02", "L-03", "L-04", "L-05"]

    first = listing["items"][0]
    assert (await client.get(f"{url}/{first['id']}")).json() == first
    assert (await client.get(f"{url}/missing")).status_code == 404
    assert (await client.get(f"{API}/networks/missing/links")).status_code == 404


async def test_patch_link(client: AsyncClient, pair: dict[str, Any]) -> None:
    created = (await client.post(pair["url"], json=link_payload(pair["a"], pair["b"]))).json()
    before = await network_version(client, pair["network_id"])

    response = await client.patch(
        f"{pair['url']}/{created['id']}",
        json={"bidirectional": False, "allowed_ports": [22, 443], "target_asset_id": pair["c"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["bidirectional"] is False
    assert body["allowed_ports"] == [22, 443]
    assert body["target_asset_id"] == pair["c"]
    assert body["code"] == "L-1"
    assert await network_version(client, pair["network_id"]) == before + 1


async def test_patch_link_errors(client: AsyncClient, pair: dict[str, Any]) -> None:
    created = (await client.post(pair["url"], json=link_payload(pair["a"], pair["b"]))).json()
    await client.post(pair["url"], json=link_payload(pair["b"], pair["c"], code="L-2"))
    url = f"{pair['url']}/{created['id']}"
    before = await network_version(client, pair["network_id"])

    self_link = await client.patch(url, json={"target_asset_id": pair["a"]})
    assert self_link.status_code == 422
    assert self_link.json()["error"]["details"]["errors"]
    assert (await client.patch(url, json={"target_asset_id": "missing"})).status_code == 422
    assert (await client.patch(url, json={"type": None})).status_code == 422
    assert (await client.patch(url, json={"code": "L-2"})).status_code == 409
    assert (await client.patch(f"{pair['url']}/missing", json={"code": "Z"})).status_code == 404

    assert await network_version(client, pair["network_id"]) == before


async def test_delete_link(client: AsyncClient, pair: dict[str, Any]) -> None:
    created = (await client.post(pair["url"], json=link_payload(pair["a"], pair["b"]))).json()
    before = await network_version(client, pair["network_id"])
    url = f"{pair['url']}/{created['id']}"

    assert (await client.delete(url)).status_code == 204
    assert (await client.get(url)).status_code == 404
    assert (await client.delete(url)).status_code == 404
    assert await network_version(client, pair["network_id"]) == before + 1
