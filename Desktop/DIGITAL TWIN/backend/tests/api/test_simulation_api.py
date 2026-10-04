"""Scenario, simulate, run and replay endpoints."""

from typing import Any

from httpx import AsyncClient

from tests.conftest import API, create_network, network_version


async def simulate(client: AsyncClient, network_id: str, **body: Any) -> Any:
    return await client.post(f"{API}/networks/{network_id}/simulate", json=body)


async def control(client: AsyncClient, network_id: str, code: str) -> dict[str, Any]:
    items = (await client.get(f"{API}/networks/{network_id}/controls")).json()["items"]
    return next(item for item in items if item["code"] == code)


async def test_list_and_get_scenarios(client: AsyncClient) -> None:
    listing = (await client.get(f"{API}/scenarios")).json()
    assert listing["total"] == 6
    assert [item["code"] for item in listing["items"]] == ["S1", "S2", "S3", "S4", "S5", "S6"]
    first = listing["items"][0]
    assert set(first) == {
        "id", "code", "name", "description", "attacker_profile", "entry", "goal",
        "initial_effects", "steps", "tags",
    }
    assert set(first["steps"][0]) >= {
        "order", "name", "technique_id", "tactic", "layer", "protocol", "port", "service",
        "preconditions", "on_success", "notes", "target_code", "target_selector",
    }

    page = (await client.get(f"{API}/scenarios", params={"limit": 2, "offset": 4})).json()
    assert (page["total"], [item["code"] for item in page["items"]]) == (6, ["S5", "S6"])

    by_id = await client.get(f"{API}/scenarios/{first['id']}")
    by_code = await client.get(f"{API}/scenarios/S1")
    assert by_id.status_code == 200 and by_id.json() == by_code.json() == first

    missing = await client.get(f"{API}/scenarios/S99")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"


async def test_simulate_returns_and_stores_a_run(client: AsyncClient, acme_id: str) -> None:
    response = await simulate(client, acme_id, scenario_id="S3")
    assert response.status_code == 201
    run = response.json()

    assert (run["status"], run["final_outcome"], run["seed"]) == ("completed", "objective_reached", 42)
    assert (run["network_id"], run["network_version"], run["scenario_code"]) == (acme_id, 1, "S3")
    assert (run["furthest_asset_code"], run["deepest_zone"]) == ("DB-01", "server")
    assert run["first_detection"]["control_code"] == "WAF-01"
    assert run["error"] is None
    assert len(run["step_results"]) == 5
    step = run["step_results"][0]
    assert set(step) == {
        "step_order", "technique_id", "technique_name", "tactic", "source_code", "target_code",
        "link_code", "connectivity", "control_results", "outcome", "chosen_path",
        "alternatives_tried", "offset_seconds", "effects_applied", "position_after", "note",
    }
    assert step["technique_name"] == "Exploit Public-Facing Application"
    assert step["connectivity"] == {
        "allowed": True,
        "deciding_control_code": "FW-EDGE",
        "reason": "FW-EDGE rule 0 allows internet -> dmz port 443",
    }
    assert len(step["control_results"]) == 14

    stored = await client.get(f"{API}/runs/{run['id']}")
    assert stored.status_code == 200
    assert stored.json() == run


async def test_same_seed_gives_identical_step_results(client: AsyncClient, acme_id: str) -> None:
    first = (await simulate(client, acme_id, scenario_id="S1", seed=7)).json()
    second = (await simulate(client, acme_id, scenario_id="S1", seed=7)).json()
    assert first["id"] != second["id"]
    for field in ("step_results", "final_outcome", "path_taken", "effects_gained", "first_detection"):
        assert first[field] == second[field]


async def test_simulate_errors(client: AsyncClient, acme_id: str) -> None:
    assert (await simulate(client, acme_id, scenario_id="S99")).status_code == 404
    assert (await simulate(client, "missing", scenario_id="S1")).status_code == 404
    assert (await simulate(client, acme_id)).status_code == 422
    assert (await simulate(client, acme_id, scenario_id="S1", seed="abc")).status_code == 422
    assert (await client.get(f"{API}/networks/{acme_id}/runs")).json()["total"] == 0


async def test_simulation_on_a_network_that_lacks_the_assets_is_a_failed_run(client: AsyncClient) -> None:
    network = await create_network(client, "empty")
    response = await simulate(client, network["id"], scenario_id="S5")
    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "failed"
    assert run["error"] == "EngineError: asset WS-03 does not exist in this network"
    assert run["step_results"] == [] and run["final_outcome"] is None

    events = (await client.get(f"{API}/runs/{run['id']}/events")).json()["events"]
    assert [item["type"] for item in events] == ["start", "end"]
    assert (events[-1]["outcome"], events[-1]["title"]) == ("failed", "Simulation failed")


async def test_waf_mode_changes_s3_from_reached_to_contained(client: AsyncClient, acme_id: str) -> None:
    before = (await simulate(client, acme_id, scenario_id="S3")).json()
    assert before["final_outcome"] == "objective_reached"

    waf = await control(client, acme_id, "WAF-01")
    patched = await client.patch(f"{API}/networks/{acme_id}/controls/{waf['id']}", json={"config": {"mode": "block"}})
    assert patched.status_code == 200

    after = (await simulate(client, acme_id, scenario_id="S3")).json()
    assert (after["final_outcome"], after["network_version"]) == ("contained", 2)
    assert [step["outcome"] for step in after["step_results"]] == ["blocked"]


async def test_runs_keep_their_version_and_do_not_change(client: AsyncClient, acme_id: str) -> None:
    run = (await simulate(client, acme_id, scenario_id="S1")).json()
    assert run["network_version"] == 1

    swsec = await control(client, acme_id, "SWSEC-2")
    await client.patch(f"{API}/networks/{acme_id}/controls/{swsec['id']}", json={"config": {"dynamic_arp_inspection": True}})
    assert await network_version(client, acme_id) == 2

    assert (await client.get(f"{API}/runs/{run['id']}")).json() == run
    rerun = (await simulate(client, acme_id, scenario_id="S1")).json()
    assert (rerun["network_version"], rerun["final_outcome"]) == (2, "contained")
    assert (await client.get(f"{API}/runs/{run['id']}")).json()["final_outcome"] == "objective_reached"

    url = f"{API}/runs/{run['id']}"
    for method in ("put", "patch", "delete"):
        assert (await getattr(client, method)(url)).status_code == 405
    assert (await client.post(url, json={})).status_code == 405


async def test_simulate_all(client: AsyncClient, acme_id: str) -> None:
    response = await client.post(f"{API}/networks/{acme_id}/simulate-all")
    assert response.status_code == 201
    body = response.json()
    assert (body["network_id"], body["network_version"], body["seed"]) == (acme_id, 1, 42)
    summary = {item["scenario_code"]: item for item in body["runs"]}
    assert list(summary) == ["S1", "S2", "S3", "S4", "S5", "S6"]
    assert {code: item["final_outcome"] for code, item in summary.items()} == {
        "S1": "objective_reached",
        "S2": "contained",
        "S3": "objective_reached",
        "S4": "objective_reached",
        "S5": "objective_reached",
        "S6": "objective_reached",
    }
    assert all(item["status"] == "completed" and item["error"] is None for item in body["runs"])
    assert (summary["S2"]["steps_executed"], summary["S2"]["steps_blocked"]) == (1, 1)
    assert (summary["S1"]["steps_executed"], summary["S1"]["steps_detected"]) == (5, 4)
    assert summary["S6"]["first_detection"] is None
    assert "step_results" not in summary["S1"]

    seeded = await client.post(f"{API}/networks/{acme_id}/simulate-all", json={"seed": 7})
    assert seeded.json()["seed"] == 7
    assert (await client.post(f"{API}/networks/missing/simulate-all")).status_code == 404


async def test_list_runs_with_scenario_filter(client: AsyncClient, acme_id: str) -> None:
    await client.post(f"{API}/networks/{acme_id}/simulate-all")
    extra = (await simulate(client, acme_id, scenario_id="S3", seed=5)).json()
    url = f"{API}/networks/{acme_id}/runs"

    everything = (await client.get(url)).json()
    assert everything["total"] == 7
    assert "step_results" not in everything["items"][0]

    by_code = (await client.get(url, params={"scenario_id": "S3"})).json()
    assert by_code["total"] == 2
    assert {item["scenario_code"] for item in by_code["items"]} == {"S3"}
    by_id = (await client.get(url, params={"scenario_id": extra["scenario_id"]})).json()
    assert by_id["total"] == 2

    page = (await client.get(url, params={"limit": 3, "offset": 6})).json()
    assert (page["total"], len(page["items"])) == (7, 1)

    assert (await client.get(url, params={"scenario_id": "S99"})).status_code == 404
    assert (await client.get(f"{API}/networks/missing/runs")).status_code == 404
    assert (await client.get(f"{API}/runs/missing")).status_code == 404


async def test_events_are_an_ordered_replay_stream(client: AsyncClient, acme_id: str) -> None:
    run = (await simulate(client, acme_id, scenario_id="S3")).json()
    response = await client.get(f"{API}/runs/{run['id']}/events")
    assert response.status_code == 200
    body = response.json()
    assert (body["run_id"], body["scenario_code"], body["status"]) == (run["id"], "S3", "completed")

    events = body["events"]
    assert [item["type"] for item in events] == ["start", "step", "step", "step", "step", "step", "end"]
    assert [item["sequence"] for item in events] == list(range(7))
    offsets = [item["offset_seconds"] for item in events]
    assert offsets == sorted(offsets) and offsets[0] == 0
    assert [item["step_order"] for item in events[1:-1]] == [1, 2, 3, 4, 5]

    start, first, end = events[0], events[1], events[-1]
    assert (start["position"], start["cumulative_path"]) == ("INTERNET", ["INTERNET"])
    assert (first["source_code"], first["target_code"], first["outcome"]) == ("INTERNET", "WEB-01", "detected_not_blocked")
    assert first["connectivity_allowed"] is True
    assert first["control_badges"] == [
        {"control_code": "WAF-01", "outcome": "detected", "confidence": 0.8},
        {"control_code": "IDS-01", "outcome": "detected", "confidence": 0.6},
    ]
    assert first["path"] == ["INTERNET", "FW-EDGE", "WEB-01"]
    assert first["cumulative_path"] == ["INTERNET", "FW-EDGE", "WEB-01"]
    assert first["effects"] == ["gain_foothold"]

    lengths = [len(item["cumulative_path"]) for item in events]
    assert lengths == sorted(lengths)
    assert end["cumulative_path"] == run["path_taken"]
    assert (end["outcome"], end["title"], end["position"]) == ("objective_reached", "Attack objective reached", "DB-01")
    assert end["offset_seconds"] == run["step_results"][-1]["offset_seconds"]

    assert (await client.get(f"{API}/runs/missing/events")).status_code == 404


async def test_events_for_a_step_that_does_not_move_and_a_blocked_run(client: AsyncClient, acme_id: str) -> None:
    insider = (await simulate(client, acme_id, scenario_id="S6")).json()
    events = (await client.get(f"{API}/runs/{insider['id']}/events")).json()["events"]
    assert [item["cumulative_path"] for item in events] == [["ADMIN-01"]] * 4
    assert events[1]["control_badges"] == []
    assert events[2]["effects"] == ["exfiltrate_data"]

    phish = (await simulate(client, acme_id, scenario_id="S2")).json()
    events = (await client.get(f"{API}/runs/{phish['id']}/events")).json()["events"]
    assert [item["type"] for item in events] == ["start", "step", "end"]
    assert events[1]["outcome"] == "blocked"
    assert events[1]["control_badges"][0] == {"control_code": "MAIL-01", "outcome": "blocked", "confidence": 0.7}
    assert (events[2]["outcome"], events[2]["cumulative_path"]) == ("contained", ["INTERNET"])


async def test_deleting_a_network_deletes_its_runs(client: AsyncClient, acme_id: str) -> None:
    run = (await simulate(client, acme_id, scenario_id="S2")).json()
    assert (await client.delete(f"{API}/networks/{acme_id}")).status_code == 204
    assert (await client.get(f"{API}/runs/{run['id']}")).status_code == 404
