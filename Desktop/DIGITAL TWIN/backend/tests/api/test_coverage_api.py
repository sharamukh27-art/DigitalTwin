"""Coverage endpoint."""

from typing import Any

from httpx import AsyncClient

from tests.conftest import API, create_network


def cell(body: dict[str, Any], technique_id: str, control_code: str) -> dict[str, Any]:
    row = next(row for row in body["matrix"] if row["technique_id"] == technique_id)
    return next(item for item in row["cells"] if item["control_code"] == control_code)


async def test_coverage_shows_all_five_planted_gaps(client: AsyncClient, acme_id: str) -> None:
    response = await client.get(f"{API}/networks/{acme_id}/coverage")
    assert response.status_code == 200
    body = response.json()

    assert set(body) == {
        "matrix",
        "uncovered_techniques",
        "weakly_covered",
        "coverage_percent",
        "placement_gaps",
    }
    assert len(body["matrix"]) == 14
    assert set(body["matrix"][0]) == {"technique_id", "technique_name", "tactic", "cells"}
    assert body["coverage_percent"] == 85.7
    assert body["uncovered_techniques"] == ["T1133"]
    assert body["weakly_covered"] == ["T1005"]

    gap_1 = cell(body, "T1190", "WAF-01")
    assert (gap_1["action"], gap_1["downgraded_from"], gap_1["status"]) == ("detect", "block", "active")

    gap_2 = cell(body, "T1599", "NAC-01")
    assert (gap_2["status"], gap_2["reason"]) == (
        "missed_requirement",
        "mac_auth_bypass_allowed is true on NAC-01",
    )

    gap_3 = cell(body, "T1557.002", "SWSEC-2")
    assert (gap_3["status"], gap_3["reason"]) == (
        "missed_requirement",
        "dynamic_arp_inspection is false on SWSEC-2",
    )

    gap_4 = cell(body, "T1133", "MFA-01")
    assert (gap_4["status"], gap_4["reason"]) == (
        "missed_requirement",
        "enforced_for does not contain vpn on MFA-01",
    )

    gap_5 = [gap for gap in body["placement_gaps"] if gap["asset_code"] == "FS-01"]
    assert len(gap_5) == 1
    assert (gap_5[0]["kind"], gap_5[0]["control_type"]) == ("host", "edr")


async def test_coverage_follows_control_changes(client: AsyncClient, acme_id: str) -> None:
    controls_url = f"{API}/networks/{acme_id}/controls"
    items = {item["code"]: item for item in (await client.get(controls_url)).json()["items"]}

    patched = await client.patch(
        f"{controls_url}/{items['MFA-01']['id']}",
        json={
            "config": {"enforced_for": ["email", "ad", "vpn"]},
            "placement": {"kind": "identity", "services": ["email", "ad", "vpn"]},
        },
    )
    assert patched.status_code == 200

    body = (await client.get(f"{API}/networks/{acme_id}/coverage")).json()
    assert body["uncovered_techniques"] == []
    assert body["coverage_percent"] == 92.9
    assert cell(body, "T1133", "MFA-01")["status"] == "active"


async def test_coverage_of_empty_and_unknown_network(client: AsyncClient) -> None:
    network = await create_network(client)
    body = (await client.get(f"{API}/networks/{network['id']}/coverage")).json()
    assert body["coverage_percent"] == 0.0
    assert len(body["uncovered_techniques"]) == 14
    assert body["placement_gaps"] == []

    assert (await client.get(f"{API}/networks/missing/coverage")).status_code == 404
