"""Endpoints added for the dashboard: posture history and controls on graph nodes."""

from httpx import AsyncClient

from app.controls.placement import protecting_controls
from app.models.asset import Asset
from app.models.control import SecurityControl
from tests.conftest import API, create_network

DAI = "Enable dynamic ARP inspection on SWSEC-2"


async def test_graph_nodes_list_their_protecting_controls(client: AsyncClient, acme_id: str) -> None:
    nodes = {n["data"]["code"]: n for n in (await client.get(f"{API}/networks/{acme_id}/graph")).json()["nodes"]}

    assert [c["code"] for c in nodes["WEB-01"]["controls"]] == ["IDS-01", "SEG-01", "SIEM-01", "WAF-01"]
    assert nodes["WEB-01"]["controls"][3] == {
        "code": "WAF-01", "name": "Web application firewall", "type": "waf", "kind": "inline", "enabled": True,
    }
    assert [c["code"] for c in nodes["FS-01"]["controls"]] == ["BKP-01", "IDS-01", "SEG-01", "SIEM-01"]
    assert "EDR-01" in [c["code"] for c in nodes["WS-03"]["controls"]]
    assert "EDR-01" not in [c["code"] for c in nodes["FS-01"]["controls"]]
    assert [c["code"] for c in nodes["SW-ACCESS-2"]["controls"]] == ["NAC-01", "SEG-01", "SIEM-01", "SWSEC-2"]
    assert [c["code"] for c in nodes["GUEST-DEV"]["controls"]] == ["SEG-01", "SIEM-01"]
    assert all("MFA-01" not in [c["code"] for c in node["controls"]] for node in nodes.values())


def test_protecting_controls_by_placement_kind(acme_assets: dict[str, Asset], acme_controls: dict[str, SecurityControl]) -> None:
    controls = list(acme_controls.values())
    assert [c.code for c in protecting_controls(acme_assets["DB-01"], controls)] == ["BKP-01", "IDS-01", "SEG-01", "SIEM-01"]
    assert protecting_controls(acme_assets["DB-01"], []) == []


async def test_posture_history_records_one_snapshot_per_version(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/posture/history"
    assert (await client.get(url)).json() == {"items": [], "total": 0}

    await client.get(f"{API}/networks/{acme_id}/posture", params={"refresh": "false"})
    assert (await client.get(url)).json()["total"] == 0

    await client.get(f"{API}/networks/{acme_id}/posture")
    await client.get(f"{API}/networks/{acme_id}/posture")
    first = (await client.get(url)).json()
    assert first["total"] == 1
    snapshot = first["items"][0]
    assert set(snapshot) == {
        "network_id", "network_version", "posture_score", "average_risk", "coverage_percent",
        "scenarios_contained", "scenarios_partially_contained", "scenarios_reached", "recorded_at",
    }
    assert (snapshot["network_version"], snapshot["posture_score"], snapshot["average_risk"]) == (1, 57, 40.67)
    assert (snapshot["scenarios_contained"], snapshot["scenarios_partially_contained"], snapshot["scenarios_reached"]) == (1, 0, 5)

    runs = (await client.get(f"{API}/networks/{acme_id}/runs", params={"scenario_id": "S1"})).json()["items"]
    fixes = (await client.post(f"{API}/runs/{runs[0]['id']}/remediations")).json()["items"]
    fix = next(item for item in fixes if item["title"] == DAI)
    await client.post(f"{API}/remediations/{fix['id']}/verify")
    await client.patch(f"{API}/remediations/{fix['id']}", json={"status": "approved", "actor": "alice"})

    history = (await client.get(url)).json()["items"]
    assert [(item["network_version"], item["posture_score"]) for item in history] == [(1, 57), (2, 63)]
    assert (history[1]["scenarios_contained"], history[1]["scenarios_reached"]) == (2, 4)

    assert (await client.get(f"{API}/networks/missing/posture/history")).status_code == 404
    empty = await create_network(client, "empty")
    assert (await client.get(f"{API}/networks/{empty['id']}/posture/history")).json()["total"] == 0
    assert (await client.delete(f"{API}/networks/{acme_id}")).status_code == 204
