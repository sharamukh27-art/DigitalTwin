"""Findings, risk, posture, what-if and sandbox endpoints."""

from typing import Any

import pytest
from httpx import AsyncClient

from app.analysis.risk import round_half_up
from tests.conftest import API, create_network, network_version

DAI_ON = {"target": "control", "code": "SWSEC-2", "set": {"config.dynamic_arp_inspection": True}}


async def run_scenario(client: AsyncClient, network_id: str, code: str) -> dict[str, Any]:
    response = await client.post(f"{API}/networks/{network_id}/simulate", json={"scenario_id": code})
    assert response.status_code == 201
    return response.json()


async def network_count(client: AsyncClient) -> int:
    return int((await client.get(f"{API}/networks")).json()["total"])


@pytest.mark.parametrize("code", ["S1", "S2", "S3", "S4", "S5", "S6"])
async def test_every_run_has_findings_and_a_risk_that_adds_up(client: AsyncClient, acme_id: str, code: str) -> None:
    run = await run_scenario(client, acme_id, code)

    findings = (await client.get(f"{API}/runs/{run['id']}/findings")).json()
    assert set(findings) >= {
        "run_id", "scenario_code", "network_version", "containment", "first_detection_step",
        "time_to_detect_seconds", "first_block_step", "detecting_controls", "blocking_controls",
        "missed_controls", "not_seen_gaps", "attack_depth", "blast_radius", "effects_gained",
        "weakest_link", "killchain",
    }
    assert (findings["run_id"], findings["scenario_code"], findings["containment"]) == (
        run["id"], code, run["final_outcome"],
    )
    assert set(findings["blast_radius"]) >= {"asset_codes", "count", "criticality_sum", "max_criticality", "data_assets_reached"}
    assert len(findings["killchain"]) == len(run["step_results"])
    if code == "S2":
        assert findings["weakest_link"] is None and findings["blast_radius"]["count"] == 0
    else:
        assert set(findings["weakest_link"]) == {"kind", "ref", "step_order", "explanation"}
        assert findings["blast_radius"]["count"] >= 1

    risk = (await client.get(f"{API}/runs/{run['id']}/risk")).json()
    assert set(risk) == {"score", "band", "likelihood", "impact", "breakdown"}
    breakdown = risk["breakdown"]
    likelihood = sum(factor["contribution"] for factor in breakdown["likelihood_factors"])
    impact = sum(factor["contribution"] for factor in breakdown["impact_factors"])
    assert likelihood == pytest.approx(risk["likelihood"])
    assert impact == pytest.approx(risk["impact"])
    assert round_half_up(likelihood * impact * 100) == risk["score"]
    for factor in breakdown["likelihood_factors"] + breakdown["impact_factors"]:
        assert set(factor) == {"name", "raw", "weight", "contribution", "detail"}
        assert factor["contribution"] == pytest.approx(factor["raw"] * factor["weight"], abs=1e-6)


async def test_findings_are_cached_and_survive_twin_changes(client: AsyncClient, acme_id: str) -> None:
    run = await run_scenario(client, acme_id, "S1")
    url = f"{API}/runs/{run['id']}/findings"
    first = (await client.get(url)).json()
    assert first["weakest_link"]["ref"] == "SWSEC-2"

    controls = (await client.get(f"{API}/networks/{acme_id}/controls")).json()["items"]
    swsec = next(item for item in controls if item["code"] == "SWSEC-2")
    await client.patch(f"{API}/networks/{acme_id}/controls/{swsec['id']}", json={"name": "Renamed"})

    assert (await client.get(url)).json() == first
    risk = (await client.get(f"{API}/runs/{run['id']}/risk")).json()
    assert (risk["score"], risk["band"]) == (39, "medium")


async def test_findings_and_risk_errors(client: AsyncClient) -> None:
    assert (await client.get(f"{API}/runs/missing/findings")).status_code == 404
    assert (await client.get(f"{API}/runs/missing/risk")).status_code == 404

    network = await create_network(client, "empty")
    failed = await run_scenario(client, network["id"], "S1")
    assert failed["status"] == "failed"
    for path in ("findings", "risk"):
        response = await client.get(f"{API}/runs/{failed['id']}/{path}")
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
        assert "no findings" in response.json()["error"]["message"]


async def test_posture(client: AsyncClient, acme_id: str) -> None:
    response = await client.get(f"{API}/networks/{acme_id}/posture")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "network_id", "network_version", "posture_score", "per_scenario", "average_risk",
        "coverage_percent", "top_risks", "worst_weakest_links", "stale_scenarios", "breakdown",
    }
    assert (body["posture_score"], body["average_risk"], body["coverage_percent"]) == (57, 40.67, 85.7)
    assert [(item["scenario_code"], item["risk_score"], item["containment"]) for item in body["per_scenario"]] == [
        ("S1", 39, "objective_reached"), ("S2", 0, "contained"), ("S3", 51, "objective_reached"),
        ("S4", 46, "objective_reached"), ("S5", 52, "objective_reached"), ("S6", 56, "objective_reached"),
    ]
    assert [item["scenario_code"] for item in body["top_risks"]] == ["S6", "S5", "S3"]
    assert body["stale_scenarios"] == []
    assert sum(item["count"] for item in body["worst_weakest_links"]) == 5

    breakdown = body["breakdown"]
    expected = round_half_up(breakdown["base_score"] * breakdown["coverage_factor"])
    assert expected == body["posture_score"]
    assert breakdown["base_score"] == pytest.approx(100 - body["average_risk"])
    assert "coverage_factor" in breakdown["formula"]

    assert (await client.get(f"{API}/networks/{acme_id}/runs")).json()["total"] == 6
    assert (await client.get(f"{API}/networks/{acme_id}/posture")).json() == body
    assert (await client.get(f"{API}/networks/{acme_id}/runs")).json()["total"] == 6


async def test_posture_without_refresh_and_errors(client: AsyncClient, acme_id: str) -> None:
    body = (await client.get(f"{API}/networks/{acme_id}/posture", params={"refresh": "false"})).json()
    assert len(body["stale_scenarios"]) == 6 and body["per_scenario"] == []
    assert (await client.get(f"{API}/networks/{acme_id}/runs")).json()["total"] == 0
    assert (await client.get(f"{API}/networks/missing/posture")).status_code == 404


async def test_whatif_on_a_planted_gap(client: AsyncClient, acme_id: str) -> None:
    response = await client.post(f"{API}/networks/{acme_id}/whatif", json={"patch": [DAI_ON]})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"network_id", "seed", "patch", "before", "after", "diff", "summary", "sandbox_id"}
    assert (body["network_id"], body["seed"], body["sandbox_id"]) == (acme_id, 42, None)

    s1 = body["diff"][0]
    assert s1 == {
        "scenario_code": "S1", "risk_before": 39, "risk_after": 0, "delta": -39,
        "containment_before": "objective_reached", "containment_after": "contained",
        "steps_changed": s1["steps_changed"],
    }
    assert s1["steps_changed"][0] == {"step_order": 1, "from_outcome": "detected_not_blocked", "to_outcome": "blocked"}
    assert all(item["delta"] <= 0 for item in body["diff"])
    assert body["summary"] == {
        "total_risk_delta": -39, "scenarios_improved": 1, "scenarios_worsened": 0, "scenarios_unchanged": 5,
    }
    assert set(body["before"]) == {"per_scenario", "posture"}
    assert body["after"]["posture"]["posture_score"] > body["before"]["posture"]["posture_score"]

    assert await network_count(client) == 1
    assert await network_version(client, acme_id) == 1
    assert (await client.get(f"{API}/networks/{acme_id}/runs")).json()["total"] == 0
    controls = (await client.get(f"{API}/networks/{acme_id}/controls")).json()["items"]
    assert next(c for c in controls if c["code"] == "SWSEC-2")["config"]["dynamic_arp_inspection"] is False


async def test_whatif_with_scenarios_seed_and_keep(client: AsyncClient, acme_id: str) -> None:
    response = await client.post(
        f"{API}/networks/{acme_id}/whatif",
        params={"keep": "true"},
        json={
            "patch": [{"target": "control", "code": "WAF-01", "set": {"config.mode": "block"}}],
            "scenario_ids": ["S3"],
            "seed": 7,
        },
    )
    body = response.json()
    assert response.status_code == 200
    assert (body["seed"], [item["scenario_code"] for item in body["diff"]]) == (7, ["S3"])
    assert (body["diff"][0]["containment_before"], body["diff"][0]["containment_after"]) == ("objective_reached", "contained")

    sandbox_id = body["sandbox_id"]
    assert sandbox_id and await network_count(client) == 2
    sandbox = (await client.get(f"{API}/networks/{sandbox_id}")).json()
    assert (sandbox["is_sandbox"], sandbox["parent_network_id"], sandbox["version"]) == (True, acme_id, 2)
    assert (await client.get(f"{API}/networks/{sandbox_id}/runs")).json()["total"] == 2
    kept_run = body["after"]["per_scenario"][0]["run_id"]
    assert (await client.get(f"{API}/runs/{kept_run}/findings")).status_code == 200

    assert (await client.delete(f"{API}/networks/{sandbox_id}")).status_code == 204
    assert await network_count(client) == 1
    assert (await client.get(f"{API}/runs/{kept_run}")).status_code == 404
    assert (await client.get(f"{API}/runs/{kept_run}/findings")).status_code == 404


async def test_whatif_errors_leave_no_sandbox_behind(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/whatif"

    bad_value = await client.post(url, json={"patch": [{"target": "control", "code": "WAF-01", "set": {"config.mode": "x"}}]})
    assert bad_value.status_code == 422
    assert bad_value.json()["error"]["message"] == "Patch is not valid. Nothing was changed."
    assert "patch[0] (control WAF-01)" in bad_value.json()["error"]["details"]["errors"][0]

    assert (await client.post(url, json={"patch": [{"target": "control", "code": "NOPE", "set": {"enabled": False}}]})).status_code == 422
    assert (await client.post(url, json={"patch": []})).status_code == 422
    assert (await client.post(url, json={})).status_code == 422
    assert (await client.post(url, json={"patch": [{"target": "link", "code": "L-01", "set": {"type": "wifi"}}]})).status_code == 422
    assert (await client.post(url, json={"patch": [{"target": "control", "code": "WAF-01", "set": {}}]})).status_code == 422
    assert (await client.post(url, json={"patch": [DAI_ON], "scenario_ids": ["S99"]})).status_code == 404
    assert (await client.post(f"{API}/networks/missing/whatif", json={"patch": [DAI_ON]})).status_code == 404

    assert await network_count(client) == 1
    assert await network_version(client, acme_id) == 1


async def test_sandbox_endpoint_creates_a_cleanable_copy(client: AsyncClient, acme_id: str) -> None:
    response = await client.post(f"{API}/networks/{acme_id}/sandbox")
    assert response.status_code == 201
    sandbox = response.json()
    assert (sandbox["is_sandbox"], sandbox["parent_network_id"], sandbox["version"]) == (True, acme_id, 1)
    assert sandbox["id"] != acme_id

    for collection, total in (("assets", 25), ("links", 24), ("controls", 14)):
        assert (await client.get(f"{API}/networks/{sandbox['id']}/{collection}")).json()["total"] == total
    coverage = (await client.get(f"{API}/networks/{sandbox['id']}/coverage")).json()
    assert coverage["coverage_percent"] == 85.7
    run = await run_scenario(client, sandbox["id"], "S1")
    assert run["final_outcome"] == "objective_reached"

    assert (await client.delete(f"{API}/networks/{sandbox['id']}")).status_code == 204
    assert await network_count(client) == 1
    assert (await client.get(f"{API}/networks/{acme_id}/assets")).json()["total"] == 25
    assert (await client.get(f"{API}/runs/{run['id']}")).status_code == 404
    assert (await client.post(f"{API}/networks/missing/sandbox")).status_code == 404
