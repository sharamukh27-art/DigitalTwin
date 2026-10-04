"""Remediation endpoints: generate, verify, bundle, decide, export and audit log."""

from typing import Any

from httpx import AsyncClient

from app.rag.documents import IngestSummary
from tests.conftest import API, create_network, network_version

DAI = "Enable dynamic ARP inspection on SWSEC-2"
NAC = "Disable MAC authentication bypass on NAC-01"
LOCKOUT = "Set an account lockout threshold on IDP-01"


async def generate(client: AsyncClient, network_id: str, scenario: str) -> dict[str, dict[str, Any]]:
    run = (await client.post(f"{API}/networks/{network_id}/simulate", json={"scenario_id": scenario})).json()
    response = await client.post(f"{API}/runs/{run['id']}/remediations")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["total"] == len(body["items"])
    return {item["title"]: item for item in body["items"]}


async def decide(client: AsyncClient, remediation_id: str, **body: Any) -> Any:
    return await client.patch(f"{API}/remediations/{remediation_id}", json=body)


async def test_generate_and_read(client: AsyncClient, acme_id: str, kb_index: IngestSummary) -> None:
    found = await generate(client, acme_id, "S1")
    assert len(found) == 9
    dai = found[DAI]
    assert set(dai) == {
        "id", "created_at", "updated_at", "network_id", "run_id", "scenario_code", "technique_id", "rule",
        "title", "rationale", "text_generated_by", "target", "affected_assets", "patch", "fingerprint",
        "config_snippet", "citations", "effort", "status", "verification", "risk_reduction", "priority",
        "verified_network_version", "notes", "approved_by", "approved_at",
    }
    assert (dai["status"], dai["effort"], dai["rule"]) == ("proposed", "low", "missed_requirement")
    assert dai["target"] == {"kind": "control", "code": "SWSEC-2"}
    assert dai["patch"] == [
        {"target": "control", "code": "SWSEC-2", "set": {"config.dynamic_arp_inspection": True},
         "append": {}, "prepend": {}, "create": None}
    ]
    assert dai["config_snippet"] == "ip arp inspection vlan 10,50"
    assert dai["citations"][0] == {
        "id": "S1", "source_name": "MITRE ATT&CK",
        "source_url": "https://attack.mitre.org/techniques/T1557/002", "section_id": "T1557.002",
    }

    assert (await client.get(f"{API}/remediations/{dai['id']}")).json() == dai
    listing = (await client.get(f"{API}/networks/{acme_id}/remediations")).json()
    assert listing["total"] == 9 and [item["title"] for item in listing["items"]] == list(found)
    assert (await client.get(f"{API}/networks/{acme_id}/remediations", params={"limit": 4, "offset": 8})).json()["items"][0]["title"] == list(found)[8]

    assert (await client.post(f"{API}/runs/missing/remediations")).status_code == 404
    assert (await client.get(f"{API}/remediations/missing")).status_code == 404
    assert (await client.get(f"{API}/networks/missing/remediations")).status_code == 404
    assert (await client.get(f"{API}/networks/{acme_id}/remediations", params={"status": "done"})).status_code == 422

    empty = await create_network(client, "empty")
    failed = (await client.post(f"{API}/networks/{empty['id']}/simulate", json={"scenario_id": "S1"})).json()
    assert (await client.post(f"{API}/runs/{failed['id']}/remediations")).status_code == 422


async def test_verify_stores_before_and_after_and_ranks(client: AsyncClient, acme_id: str) -> None:
    found = {**await generate(client, acme_id, "S1"), **await generate(client, acme_id, "S4")}

    response = await client.post(f"{API}/remediations/{found[NAC]['id']}/verify")
    assert response.status_code == 200
    nac = response.json()
    assert (nac["status"], nac["risk_reduction"], nac["priority"], nac["verified_network_version"]) == ("verified", 5.34, 2.67, 1)
    assert set(nac["verification"]) == {"verified", "reasons", "network_version", "seed", "before", "after", "diff"}
    assert set(nac["verification"]["before"]) == {"per_scenario", "average_risk", "posture_score"}
    assert nac["verification"]["before"]["per_scenario"][0] == {"scenario_code": "S1", "risk_score": 39, "containment": "objective_reached"}
    assert nac["verification"]["after"]["per_scenario"][0] == {"scenario_code": "S1", "risk_score": 7, "containment": "partially_contained"}
    assert all(item["delta"] <= 0 for item in nac["verification"]["diff"])

    dai = (await client.post(f"{API}/remediations/{found[DAI]['id']}/verify")).json()
    weak = (await client.post(f"{API}/remediations/{found['Load auth signatures on IDS-01']['id']}/verify")).json()
    assert (weak["status"], weak["verification"]["verified"]) == ("proposed", False)
    assert "no improvement: S4 risk stayed at 46" in weak["notes"][-1]

    url = f"{API}/networks/{acme_id}/remediations"
    ranked = (await client.get(url)).json()["items"]
    assert [item["title"] for item in ranked[:2]] == [DAI, NAC]
    assert [item["status"] for item in ranked[:3]] == ["verified", "verified", "proposed"]
    verified = (await client.get(url, params={"status": "verified"})).json()
    assert verified["total"] == 2 and verified["items"][0]["id"] == dai["id"]
    assert (await client.get(url, params={"status": "proposed"})).json()["total"] == 10

    assert (await client.post(f"{API}/remediations/missing/verify")).status_code == 404
    assert (await client.get(f"{API}/networks")).json()["total"] == 1
    assert await network_version(client, acme_id) == 1


async def test_verify_bundle(client: AsyncClient, acme_id: str) -> None:
    found = {**await generate(client, acme_id, "S1"), **await generate(client, acme_id, "S4")}
    ids = [found[DAI]["id"], found[LOCKOUT]["id"]]
    for remediation_id in ids:
        await client.post(f"{API}/remediations/{remediation_id}/verify")

    response = await client.post(f"{API}/remediations/verify-bundle", json={"ids": ids})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"remediation_ids", "network_id", "patch", "verification", "risk_reduction", "individual_risk_reductions"}
    assert (body["remediation_ids"], body["network_id"], body["risk_reduction"]) == (ids, acme_id, 11.84)
    assert body["individual_risk_reductions"] == {ids[0]: 6.5, ids[1]: 5.34}
    assert body["verification"]["verified"] is True and len(body["patch"]) == 2

    assert (await client.post(f"{API}/remediations/verify-bundle", json={"ids": []})).status_code == 422
    assert (await client.post(f"{API}/remediations/verify-bundle", json={"ids": [ids[0], ids[0]]})).status_code == 422
    assert (await client.post(f"{API}/remediations/verify-bundle", json={"ids": [ids[0], "missing"]})).status_code == 404
    assert (await client.get(f"{API}/networks")).json()["total"] == 1


async def test_approve_bumps_version_marks_applied_and_audits(client: AsyncClient, acme_id: str) -> None:
    found = await generate(client, acme_id, "S1")
    dai_id = found[DAI]["id"]

    early = await decide(client, dai_id, status="approved", actor="alice")
    assert early.status_code == 409
    assert early.json()["error"]["code"] == "CONFLICT"

    await client.post(f"{API}/remediations/{dai_id}/verify")
    posture_before = (await client.get(f"{API}/networks/{acme_id}/posture")).json()["posture_score"]

    response = await decide(client, dai_id, status="approved", actor="alice", note="CAB-42")
    assert response.status_code == 200
    applied = response.json()
    assert (applied["status"], applied["approved_by"]) == ("applied", "alice")
    assert applied["approved_at"] is not None
    assert applied["notes"][-1] == "applied to the twin as network version 2"

    assert await network_version(client, acme_id) == 2
    controls = (await client.get(f"{API}/networks/{acme_id}/controls")).json()["items"]
    assert next(c for c in controls if c["code"] == "SWSEC-2")["config"]["dynamic_arp_inspection"] is True
    posture = (await client.get(f"{API}/networks/{acme_id}/posture", params={"refresh": "false"})).json()
    assert posture["stale_scenarios"] == [] and posture["network_version"] == 2
    assert (posture_before, posture["posture_score"]) == (57, 63)

    log = (await client.get(f"{API}/networks/{acme_id}/audit-log", params={"limit": 100})).json()
    assert log["total"] == 12
    assert set(log["items"][0]) == {"id", "network_id", "actor", "action", "target", "before_hash", "after_hash", "note", "at"}
    assert [item["action"] for item in log["items"]][-3:] == ["remediation.verified", "remediation.approved", "remediation.applied"]
    last = log["items"][-1]
    assert (last["actor"], last["target"]) == ("alice", f"network:{acme_id}")
    assert last["before_hash"] != last["after_hash"] and len(last["after_hash"]) == 64
    assert log["items"][-2]["note"] == "CAB-42"
    page = (await client.get(f"{API}/networks/{acme_id}/audit-log", params={"limit": 5, "offset": 10})).json()
    assert (page["total"], len(page["items"])) == (12, 2)

    assert (await decide(client, dai_id, status="approved", actor="alice")).status_code == 409
    assert (await client.post(f"{API}/remediations/{dai_id}/verify")).status_code == 409

    await client.post(f"{API}/remediations/{found[NAC]['id']}/verify")
    stale_id = found["Switch IDS-01 from ids to ips mode"]["id"]
    assert (await client.get(f"{API}/remediations/{stale_id}")).json()["status"] == "proposed"


async def test_stale_verification_must_be_redone(client: AsyncClient, acme_id: str) -> None:
    found = {**await generate(client, acme_id, "S1"), **await generate(client, acme_id, "S4")}
    for title in (DAI, LOCKOUT):
        await client.post(f"{API}/remediations/{found[title]['id']}/verify")
    assert (await decide(client, found[DAI]["id"], status="approved", actor="alice")).status_code == 200

    stale = await decide(client, found[LOCKOUT]["id"], status="approved", actor="alice")
    assert stale.status_code == 409
    assert stale.json()["error"]["details"] == {"verified_network_version": 1, "network_version": 2}

    assert (await client.post(f"{API}/remediations/{found[LOCKOUT]['id']}/verify")).json()["verified_network_version"] == 2
    assert (await decide(client, found[LOCKOUT]["id"], status="approved", actor="alice")).json()["status"] == "applied"
    assert await network_version(client, acme_id) == 3


async def test_reject_and_request_validation(client: AsyncClient, acme_id: str) -> None:
    found = await generate(client, acme_id, "S1")
    nac_id = found[NAC]["id"]

    for bad in (
        {"status": "applied", "actor": "bob"},
        {"status": "rejected"},
        {"status": "rejected", "actor": "  "},
        {"actor": "bob"},
    ):
        assert (await decide(client, nac_id, **bad)).status_code == 422
    assert (await decide(client, "missing", status="rejected", actor="bob")).status_code == 404

    response = await decide(client, nac_id, status="rejected", actor="bob", note="printers need MAB")
    assert response.status_code == 200
    body = response.json()
    assert (body["status"], body["notes"][-1], body["approved_by"]) == ("rejected", "rejected by bob: printers need MAB", None)
    assert await network_version(client, acme_id) == 1

    log = (await client.get(f"{API}/networks/{acme_id}/audit-log", params={"limit": 100})).json()["items"]
    assert (log[-1]["action"], log[-1]["actor"], log[-1]["note"]) == ("remediation.rejected", "bob", "printers need MAB")
    assert (await decide(client, nac_id, status="rejected", actor="bob")).status_code == 409
    assert (await client.get(f"{API}/networks/{acme_id}/remediations", params={"status": "rejected"})).json()["total"] == 1
    assert (await client.get(f"{API}/networks/missing/audit-log")).status_code == 404


async def test_export_change_plan(client: AsyncClient, acme_id: str, kb_index: IngestSummary) -> None:
    url = f"{API}/networks/{acme_id}/remediations/export"
    empty = await client.get(url, params={"format": "md"})
    assert empty.status_code == 200
    assert empty.headers["content-type"] == "text/markdown; charset=utf-8"
    assert "No verified fixes yet." in empty.text

    found = {**await generate(client, acme_id, "S1"), **await generate(client, acme_id, "S4")}
    for title in (DAI, LOCKOUT):
        await client.post(f"{API}/remediations/{found[title]['id']}/verify")

    plan = (await client.get(url)).text
    assert plan.startswith("# Change plan: ACME Corp")
    assert f"## 1. {DAI}" in plan and f"## 2. {LOCKOUT}" in plan and NAC not in plan
    assert "```\nip arp inspection vlan 10,50\n```" in plan
    assert "account lockout threshold: 5 failed attempts" in plan
    assert "- Expected risk reduction: 6.5 points of average risk" in plan
    assert "- [S1] MITRE ATT&CK T1557.002: https://attack.mitre.org/techniques/T1557/002" in plan
    assert "remote_access_policy#account-lockout-and-passwords: org-policy://remote_access_policy.md#account-lockout-and-passwords" in plan
    assert "Nothing in this plan has been sent to a real device." in plan

    assert (await client.get(url, params={"format": "pdf"})).status_code == 422
    assert (await client.get(f"{API}/networks/missing/remediations/export")).status_code == 404


async def test_deleting_the_network_removes_remediations(client: AsyncClient, acme_id: str) -> None:
    found = await generate(client, acme_id, "S5")
    assert (await client.delete(f"{API}/networks/{acme_id}")).status_code == 204
    assert (await client.get(f"{API}/remediations/{found['Deploy EDR-01 to FS-01']['id']}")).status_code == 404
