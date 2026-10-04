"""Health endpoint and shared error format."""

import pytest
from httpx import AsyncClient

from app.core import db
from tests.conftest import API


async def test_health_reports_mongo_ok(client: AsyncClient) -> None:
    response = await client.get(f"{API}/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["mongo"] == "ok"
    assert body["version"]
    assert response.headers["X-Request-ID"]


async def test_health_reports_mongo_down(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def unreachable() -> bool:
        return False

    monkeypatch.setattr(db, "ping", unreachable)
    response = await client.get(f"{API}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["mongo"] == "down"


async def test_request_id_is_echoed(client: AsyncClient) -> None:
    response = await client.get(f"{API}/health", headers={"X-Request-ID": "req-123"})
    assert response.headers["X-Request-ID"] == "req-123"


async def test_unknown_route_uses_shared_error_format(client: AsyncClient) -> None:
    response = await client.get(f"{API}/does-not-exist")
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "NOT_FOUND"
    assert set(error) == {"code", "message", "details"}
