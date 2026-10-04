"""Explain and knowledge base status endpoints. Mock provider, fixture index."""

import json
from typing import Any

from httpx import AsyncClient

from app.llm.providers import MockProvider
from app.rag.documents import IngestSummary
from tests.conftest import API, create_network


async def run_scenario(client: AsyncClient, network_id: str, code: str) -> dict[str, Any]:
    response = await client.post(f"{API}/networks/{network_id}/simulate", json={"scenario_id": code})
    return response.json()


async def test_kb_status(client: AsyncClient) -> None:
    empty = await client.get(f"{API}/kb/status")
    assert empty.status_code == 200
    assert empty.json() == {
        "ready": False, "collection": "cyber_kb", "total_chunks": 0, "chunks_by_source": {},
        "chunks_by_kind": {}, "embedding_model": None, "last_ingest_at": None,
    }


async def test_kb_status_after_ingest(client: AsyncClient, kb_index: IngestSummary) -> None:
    body = (await client.get(f"{API}/kb/status")).json()
    assert (body["ready"], body["total_chunks"], body["embedding_model"]) == (True, 18, "hash-bow-256")
    assert body["chunks_by_kind"] == {"attack": 3, "d3fend": 3, "nist": 3, "policy": 9}
    assert body["chunks_by_source"]["MITRE D3FEND"] == 3
    assert body["last_ingest_at"].startswith(kb_index.ingested_at.isoformat()[:19])


async def test_explain_generates_caches_and_serves(client: AsyncClient, acme_id: str, kb_index: IngestSummary, offline_ai: MockProvider) -> None:
    run = await run_scenario(client, acme_id, "S1")
    stored_url = f"{API}/runs/{run['id']}/explanation"

    missing = await client.get(stored_url)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"

    response = await client.post(f"{API}/runs/{run['id']}/explain")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "summary", "timeline", "why_caught_or_missed", "recommendations", "citations",
        "id", "run_id", "network_id", "generated_without_llm", "provider", "model",
        "attempts", "validation_errors", "created_at",
    }
    assert (body["run_id"], body["network_id"], body["generated_without_llm"], body["provider"]) == (
        run["id"], acme_id, False, "mock",
    )
    assert "objective_reached" in body["summary"] and "risk score of 39" in body["summary"]
    assert set(body["timeline"][0]) == {"step_order", "plain_explanation", "citation_ids"}
    assert set(body["recommendations"][0]) == {
        "text", "related_control_code", "related_technique_id", "citation_ids", "effort_hint",
    }
    assert all(len(item["citation_ids"]) >= 1 for item in body["recommendations"])
    urls = {citation["source_url"] for citation in body["citations"]}
    assert "https://attack.mitre.org/techniques/T1557/002" in urls
    assert any(citation["source_name"] == "MITRE D3FEND" for citation in body["citations"])
    assert all(citation["id"].startswith("S") for citation in body["citations"])

    assert (await client.get(stored_url)).json() == body
    assert (await client.post(f"{API}/runs/{run['id']}/explain")).json() == body
    assert len(offline_ai.calls) == 1

    forced = (await client.post(f"{API}/runs/{run['id']}/explain", params={"force": "true"})).json()
    assert forced["id"] != body["id"] and len(offline_ai.calls) == 2
    assert (await client.get(stored_url)).json() == forced


async def test_explain_never_returns_an_answer_that_changes_the_score(
    client: AsyncClient, acme_id: str, kb_index: IngestSummary, offline_ai: MockProvider
) -> None:
    run = await run_scenario(client, acme_id, "S3")
    lie = {
        "summary": "Scenario S3 was contained with a risk score of 3 (low). Nothing was reached. All good.",
        "timeline": [], "why_caught_or_missed": "Everything worked.", "recommendations": [], "citations": [],
    }
    offline_ai.script = [json.dumps(lie), json.dumps(lie)]

    body = (await client.post(f"{API}/runs/{run['id']}/explain")).json()

    assert (body["generated_without_llm"], body["provider"], body["attempts"]) == (True, "template", 2)
    assert "objective_reached" in body["summary"] and "risk score of 51 (high)" in body["summary"]
    assert "risk score of 3" not in json.dumps(body["summary"])
    assert any("text states a risk score of 3 but the findings say 51" in error for error in body["validation_errors"])
    assert any("summary says 'contained'" in error for error in body["validation_errors"])
    assert all(len(item["citation_ids"]) >= 1 for item in body["recommendations"])


async def test_explain_without_an_index_still_answers(client: AsyncClient, acme_id: str) -> None:
    run = await run_scenario(client, acme_id, "S5")
    body = (await client.post(f"{API}/runs/{run['id']}/explain")).json()
    assert (body["recommendations"], body["citations"]) == ([], [])
    assert "not covered by the provided sources" in body["why_caught_or_missed"]
    assert "risk score of 52" in body["summary"]


async def test_explain_errors_and_cascade_delete(client: AsyncClient, acme_id: str, kb_index: IngestSummary) -> None:
    assert (await client.post(f"{API}/runs/missing/explain")).status_code == 404
    assert (await client.get(f"{API}/runs/missing/explanation")).status_code == 404

    empty = await create_network(client, "empty")
    failed = await run_scenario(client, empty["id"], "S1")
    rejected = await client.post(f"{API}/runs/{failed['id']}/explain")
    assert rejected.status_code == 422
    assert (await client.get(f"{API}/runs/{failed['id']}/explanation")).status_code == 404

    run = await run_scenario(client, acme_id, "S2")
    assert (await client.post(f"{API}/runs/{run['id']}/explain")).status_code == 200
    assert (await client.delete(f"{API}/networks/{acme_id}")).status_code == 204
    assert (await client.get(f"{API}/runs/{run['id']}/explanation")).status_code == 404
