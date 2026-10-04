"""Import and export endpoints."""

import json
from typing import Any

import yaml
from httpx import AsyncClient

from app.core import db
from tests.conftest import API, create_asset, create_network


def upload(content: bytes, filename: str = "twin.json") -> dict[str, Any]:
    return {"file": (filename, content, "application/octet-stream")}


async def test_import_creates_a_new_network(client: AsyncClient, acme_bytes: bytes) -> None:
    response = await client.post(f"{API}/networks/import", files=upload(acme_bytes, "acme_corp.json"))
    assert response.status_code == 201
    body = response.json()
    assert body["errors"] == []
    assert (body["assets_created"], body["links_created"], body["controls_created"]) == (25, 24, 14)

    network = (await client.get(f"{API}/networks/{body['network_id']}")).json()
    assert network["name"] == "ACME Corp"
    assert network["version"] == 1


async def test_import_yaml_file(client: AsyncClient, acme_data: dict[str, Any]) -> None:
    content = yaml.safe_dump(acme_data).encode("utf-8")
    response = await client.post(f"{API}/networks/import", files=upload(content, "acme.yaml"))
    assert response.status_code == 201
    assert response.json()["assets_created"] == 25


async def test_import_with_three_errors_returns_all_and_writes_nothing(
    client: AsyncClient, database: Any, acme_data: dict[str, Any]
) -> None:
    acme_data["assets"][2]["mac"] = "not-a-mac"
    acme_data["assets"][3]["code"] = "WEB-01"
    acme_data["links"][0]["target"] = "GHOST"
    content = json.dumps(acme_data).encode("utf-8")

    response = await client.post(f"{API}/networks/import", files=upload(content))

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_FAILED"
    errors = error["details"]["errors"]
    assert len(errors) == 4
    joined = "\n".join(errors)
    assert "MAC address" in joined
    assert "duplicate asset code 'WEB-01'" in joined
    assert "missing asset code 'GHOST'" in joined
    assert "missing asset code 'VPN-01'" in joined

    for name in (db.NETWORKS, db.ASSETS, db.LINKS, db.CONTROLS):
        assert await db.collection(name).count_documents({}) == 0
    assert (await client.get(f"{API}/networks")).json()["total"] == 0


async def test_import_rejects_unsupported_and_missing_file(client: AsyncClient) -> None:
    response = await client.post(f"{API}/networks/import", files=upload(b"a,b", "twin.csv"))
    assert response.status_code == 422
    assert "unsupported file type" in response.json()["error"]["details"]["errors"][0]

    assert (await client.post(f"{API}/networks/import")).status_code == 422


async def test_import_into_empty_network(client: AsyncClient, acme_bytes: bytes) -> None:
    network = await create_network(client, "Empty shell")
    response = await client.post(
        f"{API}/networks/{network['id']}/import", files=upload(acme_bytes, "acme_corp.json")
    )
    assert response.status_code == 201
    assert response.json()["network_id"] == network["id"]

    stored = (await client.get(f"{API}/networks/{network['id']}")).json()
    assert stored["name"] == "Empty shell"
    assert stored["version"] == 2
    assert (await client.get(f"{API}/networks/{network['id']}/assets")).json()["total"] == 25


async def test_import_into_non_empty_network_is_409(client: AsyncClient, acme_bytes: bytes) -> None:
    network = await create_network(client)
    await create_asset(client, network["id"], code="ONLY")

    response = await client.post(f"{API}/networks/{network['id']}/import", files=upload(acme_bytes))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"
    assert (await client.get(f"{API}/networks/{network['id']}/assets")).json()["total"] == 1


async def test_import_into_network_errors(client: AsyncClient, acme_bytes: bytes) -> None:
    assert (
        await client.post(f"{API}/networks/missing/import", files=upload(acme_bytes))
    ).status_code == 404

    network = await create_network(client)
    response = await client.post(f"{API}/networks/{network['id']}/import", files=upload(b"{oops"))
    assert response.status_code == 422
    assert (await client.get(f"{API}/networks/{network['id']}")).json()["version"] == 1


async def test_export_then_reimport_gives_an_identical_network(
    client: AsyncClient, acme_id: str
) -> None:
    first = await client.get(f"{API}/networks/{acme_id}/export")
    assert first.status_code == 200
    assert set(first.json()) == {"network", "assets", "links", "controls"}
    assert len(first.json()["controls"]) == 14

    imported = await client.post(f"{API}/networks/import", files=upload(first.content, "export.json"))
    assert imported.status_code == 201

    second = await client.get(f"{API}/networks/{imported.json()['network_id']}/export")
    assert second.json() == first.json()


async def test_export_unknown_network_is_404(client: AsyncClient) -> None:
    assert (await client.get(f"{API}/networks/missing/export")).status_code == 404
