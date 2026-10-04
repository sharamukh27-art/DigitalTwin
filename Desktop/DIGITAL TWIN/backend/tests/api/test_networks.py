"""Network CRUD endpoints."""

from typing import Any

from httpx import AsyncClient

from app.core import db
from tests.conftest import API, create_network


async def test_create_network(client: AsyncClient) -> None:
    response = await client.post(f"{API}/networks", json={"name": "HQ", "description": "main site"})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "HQ"
    assert body["description"] == "main site"
    assert body["version"] == 1
    assert body["is_sandbox"] is False
    assert body["parent_network_id"] is None
    assert len(body["id"]) == 36
    assert body["created_at"].endswith(("Z", "+00:00"))
    assert body["updated_at"] == body["created_at"]


async def test_create_network_without_name_is_422(client: AsyncClient) -> None:
    for payload in ({}, {"name": ""}, {"name": "   "}):
        response = await client.post(f"{API}/networks", json=payload)
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "VALIDATION_FAILED"
        assert error["details"]["errors"]


async def test_list_networks_is_paginated(client: AsyncClient) -> None:
    for index in range(3):
        await create_network(client, f"Network {index}")

    response = await client.get(f"{API}/networks")
    assert response.status_code == 200
    assert response.json()["total"] == 3
    assert len(response.json()["items"]) == 3

    page = (await client.get(f"{API}/networks", params={"limit": 2, "offset": 2})).json()
    assert page["total"] == 3
    assert len(page["items"]) == 1


async def test_list_networks_rejects_bad_paging(client: AsyncClient) -> None:
    assert (await client.get(f"{API}/networks", params={"limit": 0})).status_code == 422
    assert (await client.get(f"{API}/networks", params={"offset": -1})).status_code == 422


async def test_get_network(client: AsyncClient) -> None:
    network = await create_network(client)
    response = await client.get(f"{API}/networks/{network['id']}")
    assert response.status_code == 200
    assert response.json() == network


async def test_get_unknown_network_is_404(client: AsyncClient) -> None:
    response = await client.get(f"{API}/networks/missing")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert response.json()["error"]["details"] == {"network_id": "missing"}


async def test_patch_network_changes_fields_but_not_version(client: AsyncClient) -> None:
    network = await create_network(client)
    response = await client.patch(
        f"{API}/networks/{network['id']}", json={"name": "Renamed", "description": "new"}
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["name"], body["description"], body["version"]) == ("Renamed", "new", 1)


async def test_patch_network_errors(client: AsyncClient) -> None:
    network = await create_network(client)
    assert (await client.patch(f"{API}/networks/missing", json={"name": "x"})).status_code == 404
    response = await client.patch(f"{API}/networks/{network['id']}", json={"name": None})
    assert response.status_code == 422


async def test_delete_network_cascades(client: AsyncClient, database: Any, acme_id: str) -> None:
    other = await create_network(client, "Keep me")

    response = await client.delete(f"{API}/networks/{acme_id}")
    assert response.status_code == 204

    assert (await client.get(f"{API}/networks/{acme_id}")).status_code == 404
    assert await db.collection(db.ASSETS).count_documents({}) == 0
    assert await db.collection(db.LINKS).count_documents({}) == 0
    assert await db.collection(db.CONTROLS).count_documents({}) == 0
    assert (await client.get(f"{API}/networks/{other['id']}")).status_code == 200


async def test_delete_unknown_network_is_404(client: AsyncClient) -> None:
    assert (await client.delete(f"{API}/networks/missing")).status_code == 404
