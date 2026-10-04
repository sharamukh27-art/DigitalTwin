"""Shared fixtures: in-memory MongoDB, API client and the ACME sample network."""

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.controls import repository as control_repository
from app.core import db
from app.core.config import get_settings
from app.llm import client as llm_client
from app.llm.providers import MockProvider
from app.main import create_app
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.rag import embedding
from app.rag.documents import IngestSummary
from app.rag.ingest import build_index
from app.twin import graph, loader, repository

ACME_FILE = Path(__file__).resolve().parents[1] / "data" / "sample_networks" / "acme_corp.json"
API = "/api/v1"


KB_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "kb" / "raw"


@pytest.fixture(autouse=True)
def offline_ai(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MockProvider:
    """Keep every test offline: mock LLM, hash embedder, empty per-test Chroma folder."""
    settings = get_settings()
    monkeypatch.setattr(settings, "chroma_path", str(tmp_path / "chroma"))
    monkeypatch.setattr(settings, "llm_backoff_seconds", 0.0)
    provider = MockProvider()
    llm_client.set_provider(provider)
    embedding.set_embedder(embedding.HashEmbedder())
    yield provider
    llm_client.set_provider(None)
    embedding.set_embedder(None)


@pytest.fixture
def kb_index() -> IngestSummary:
    """Build the tiny fixture knowledge base into this test's Chroma folder."""
    return build_index(raw_dir=KB_FIXTURES)


@pytest_asyncio.fixture
async def database() -> AsyncIterator[Any]:
    """Point the application at a fresh in-memory MongoDB."""
    mock_database = AsyncMongoMockClient(tz_aware=True)["cyber_twin_test"]
    db.set_database(mock_database)
    await db.create_indexes()
    graph.clear_cache()
    yield mock_database
    db.set_database(None)
    graph.clear_cache()


@pytest_asyncio.fixture
async def client(database: Any) -> AsyncIterator[AsyncClient]:
    """HTTP client bound to the FastAPI app."""
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


@pytest.fixture
def acme_bytes() -> bytes:
    """Raw content of the ACME sample file."""
    return ACME_FILE.read_bytes()


@pytest.fixture
def acme_data(acme_bytes: bytes) -> dict[str, Any]:
    """Parsed content of the ACME sample file. Safe to mutate."""
    return json.loads(acme_bytes)


@pytest_asyncio.fixture
async def acme_id(database: Any, acme_bytes: bytes) -> str:
    """Import the ACME sample network and return its id."""
    result = await loader.import_network(acme_bytes, "acme_corp.json")
    assert result.errors == []
    assert result.network_id is not None
    return result.network_id


@pytest_asyncio.fixture
async def acme_codes(acme_id: str) -> dict[str, str]:
    """Map asset code to asset id for the imported ACME network."""
    return {asset.code: asset.id for asset in await repository.all_assets(acme_id)}


@pytest_asyncio.fixture
async def acme_controls(acme_id: str) -> dict[str, SecurityControl]:
    """Map control code to control for the imported ACME network."""
    return {control.code: control for control in await control_repository.all_controls(acme_id)}


@pytest_asyncio.fixture
async def acme_assets(acme_id: str) -> dict[str, Asset]:
    """Map asset code to asset for the imported ACME network."""
    return {asset.code: asset for asset in await repository.all_assets(acme_id)}


def asset_payload(code: str = "SRV-01", **overrides: Any) -> dict[str, Any]:
    """Build a valid asset request body."""
    payload: dict[str, Any] = {
        "code": code,
        "name": f"Asset {code}",
        "type": "server",
        "zone": "server",
        "criticality": 3,
    }
    payload.update(overrides)
    return payload


async def create_network(http_client: AsyncClient, name: str = "Test network") -> dict[str, Any]:
    """Create a network through the API and return its body."""
    response = await http_client.post(f"{API}/networks", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


async def create_asset(http_client: AsyncClient, network_id: str, **fields: Any) -> dict[str, Any]:
    """Create an asset through the API and return its body."""
    response = await http_client.post(
        f"{API}/networks/{network_id}/assets", json=asset_payload(**fields)
    )
    assert response.status_code == 201, response.text
    return response.json()


async def network_version(http_client: AsyncClient, network_id: str) -> int:
    """Return the current version of a network."""
    response = await http_client.get(f"{API}/networks/{network_id}")
    return int(response.json()["version"])
