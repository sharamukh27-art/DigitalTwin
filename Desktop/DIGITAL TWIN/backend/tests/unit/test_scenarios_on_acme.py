"""The six library scenarios run against the ACME sample, with and without its planted gaps."""

import pytest
import pytest_asyncio

from app.models.enums import FinalOutcome, StepOutcome
from app.models.run import SimulationOutcome
from app.scenarios import catalog
from app.simulation import engine
from app.simulation import repository as run_repository
from tests.sim import World, load_world
from tests.steps import make_control

REACHED, PARTIAL, CONTAINED = (
    FinalOutcome.OBJECTIVE_REACHED,
    FinalOutcome.PARTIALLY_CONTAINED,
    FinalOutcome.CONTAINED,
)
BLOCKED, DETECTED, UNDETECTED = (
    StepOutcome.BLOCKED,
    StepOutcome.DETECTED_NOT_BLOCKED,
    StepOutcome.UNDETECTED,
)


@pytest_asyncio.fixture
async def world(acme_id: str) -> World:
    return await load_world(acme_id)


def outcomes(result: SimulationOutcome) -> list[StepOutcome]:
    return [step.outcome for step in result.step_results]


@pytest.mark.parametrize(
    ("code", "final", "furthest", "deepest", "steps", "first_detection"),
    [
        ("S1", REACHED, "DB-01", "server", [DETECTED, DETECTED, DETECTED, DETECTED, UNDETECTED], (1, "NAC-01")),
        ("S2", CONTAINED, "INTERNET", "internet", [BLOCKED], (1, "MAIL-01")),
        ("S3", REACHED, "DB-01", "server", [DETECTED, DETECTED, DETECTED, UNDETECTED, UNDETECTED], (1, "WAF-01")),
        ("S4", REACHED, None, "server", [UNDETECTED, DETECTED, UNDETECTED], (2, "SIEM-01")),
        ("S5", REACHED, "FS-01", "server", [DETECTED, UNDETECTED, UNDETECTED], (1, "IDS-01")),
        ("S6", REACHED, "ADMIN-01", "management", [UNDETECTED, UNDETECTED], None),
    ],
)
def test_baseline(
    world: World,
    code: str,
    final: FinalOutcome,
    furthest: str | None,
    deepest: str,
    steps: list[StepOutcome],
    first_detection: tuple[int, str] | None,
) -> None:
    result = world.run(code)
    assert result.final_outcome == final
    assert outcomes(result) == steps
    assert result.deepest_zone.value == deepest
    if furthest is not None:
        assert result.furthest_asset_code == furthest
    else:
        assert result.furthest_asset_code in {"DB-01", "DC-01"}
    if first_detection is None:
        assert result.first_detection is None
    else:
        assert result.first_detection is not None
        assert (result.first_detection.step_order, result.first_detection.control_code) == first_detection
    assert [step.step_order for step in result.step_results] == list(range(1, len(steps) + 1))


@pytest.mark.parametrize("code", ["S1", "S2", "S3", "S4", "S5", "S6"])
def test_same_seed_is_byte_identical_and_seeds_only_change_ties(world: World, code: str) -> None:
    first = world.run(code, seed=42)
    assert world.run(code, seed=42).model_dump_json() == first.model_dump_json()

    for seed in (1, 2, 3, 99):
        other = world.run(code, seed=seed)
        assert other.final_outcome == first.final_outcome
        assert outcomes(other) == outcomes(first)
        assert [step.technique_id for step in other.step_results] == [step.technique_id for step in first.step_results]
        assert other.effects_gained == first.effects_gained
        assert world.run(code, seed=seed).model_dump_json() == other.model_dump_json()


def test_s1_walk_through_the_gaps(world: World) -> None:
    result = world.run("S1")
    arp, bridge, scan, exploit, login = result.step_results

    assert (arp.source_code, arp.target_code, arp.chosen_path) == ("GUEST-DEV", "SW-ACCESS-2", ["GUEST-DEV", "AP-01", "SW-ACCESS-2"])
    assert arp.position_after == "GUEST-DEV"
    assert {item.control_code: item.outcome.value for item in arp.control_results if item.outcome.value != "not_applicable"} == {
        "NAC-01": "detected",
        "SWSEC-2": "missed",
    }

    assert bridge.target_code in {"WS-06", "WS-07", "WS-08", "WS-09", "WS-10"}
    assert bridge.position_after == bridge.target_code
    assert "segmentation not applied" in bridge.note
    assert bridge.connectivity is not None and bridge.connectivity.allowed is True

    assert scan.position_after == bridge.target_code
    assert (exploit.target_code, login.source_code, login.target_code) == ("APP-01", "APP-01", "DB-01")
    assert login.connectivity is not None and "FW-INT rule 1 allows server -> server port 5432" in login.connectivity.reason
    assert result.effects_gained == ["obtain_credentials", "gain_foothold", "escalate_privilege", "read_data"]
    assert result.path_taken[0] == "GUEST-DEV" and result.path_taken[-1] == "DB-01"
    assert "APP-01" in result.path_taken


def test_s1_is_blocked_early_when_the_entry_switch_is_hardened(world: World) -> None:
    hardened = world.with_control("SWSEC-2", config={"dynamic_arp_inspection": True})
    world.controls = hardened
    hardened = world.with_control("NAC-01", config={"mac_auth_bypass_allowed": False})
    result = world.run("S1", controls=hardened)

    assert result.final_outcome == CONTAINED
    assert outcomes(result) == [BLOCKED]
    assert result.step_results[0].note == "blocked by SWSEC-2"
    assert result.furthest_asset_code == "GUEST-DEV"
    assert result.deepest_zone.value == "guest"
    assert result.effects_gained == []
    assert result.first_detection is not None and result.first_detection.control_code == "SWSEC-2"


def test_s1_needs_both_gaps_to_reach_the_database(world: World) -> None:
    dai_only = world.run("S1", controls=world.with_control("SWSEC-2", config={"dynamic_arp_inspection": True}))
    assert (dai_only.final_outcome, outcomes(dai_only)) == (CONTAINED, [BLOCKED])

    nac_only = world.run("S1", controls=world.with_control("NAC-01", config={"mac_auth_bypass_allowed": False}))
    assert (nac_only.final_outcome, outcomes(nac_only)) == (PARTIAL, [DETECTED, BLOCKED])
    assert nac_only.step_results[1].note.startswith("blocked by NAC-01")
    assert nac_only.effects_gained == ["obtain_credentials"]
    assert nac_only.furthest_asset_code == "GUEST-DEV"

    assert world.run("S1").furthest_asset_code == "DB-01"


def test_s1_reaches_a_corporate_asset_through_the_weak_switch(world: World) -> None:
    bridge = world.run("S1").step_results[1]
    assert bridge.outcome == DETECTED
    assert world.asset(bridge.position_after).zone.value == "corporate"
    assert "SW-ACCESS-2" in bridge.chosen_path
    reactions = {item.control_code: item.outcome.value for item in bridge.control_results}
    assert (reactions["NAC-01"], reactions["SWSEC-2"]) == ("missed", "detected")


def test_s3_waf_detect_continues_and_waf_block_contains(world: World) -> None:
    detect = world.run("S3")
    assert detect.step_results[0].outcome == DETECTED
    assert detect.step_results[0].note == "detected by WAF-01, IDS-01, not blocked"
    assert detect.final_outcome == REACHED
    assert detect.path_taken == ["INTERNET", "FW-EDGE", "WEB-01", "FW-EDGE", "FW-INT", "SW-CORE", "APP-01", "SW-CORE", "DB-01"]

    block = world.run("S3", controls=world.with_control("WAF-01", config={"mode": "block"}))
    assert outcomes(block) == [BLOCKED]
    assert block.step_results[0].note == "blocked by WAF-01"
    assert (block.final_outcome, block.furthest_asset_code, block.effects_gained) == (CONTAINED, "INTERNET", [])


def test_s3_waf_does_not_inspect_traffic_leaving_the_web_server(world: World) -> None:
    pivot = world.run("S3").step_results[2]
    assert (pivot.source_code, pivot.target_code) == ("WEB-01", "APP-01")
    waf = next(item for item in pivot.control_results if item.control_code == "WAF-01")
    assert waf.outcome.value == "not_applicable"
    assert pivot.note == "detected by IDS-01, not blocked"


def test_s4_brute_force_succeeds_without_mfa_on_vpn_and_is_blocked_with_it(world: World) -> None:
    baseline = world.run("S4")
    brute_force = baseline.step_results[1]
    assert (brute_force.technique_id, brute_force.outcome) == ("T1110", DETECTED)
    assert brute_force.effects_applied == ["obtain_credentials"]
    assert baseline.step_results[2].connectivity is not None
    assert "firewall not applied" in baseline.step_results[2].note
    assert baseline.final_outcome == REACHED

    covered = ["email", "ad", "vpn"]
    fixed = world.run("S4", controls=world.with_control("MFA-01", config={"enforced_for": covered}, services=covered))
    assert outcomes(fixed) == [BLOCKED]
    assert fixed.step_results[0].note == "blocked by MFA-01"
    assert fixed.final_outcome == CONTAINED


def test_s4_seed_decides_between_equally_near_critical_assets(world: World) -> None:
    assert {world.run("S4", seed=seed).furthest_asset_code for seed in range(20)} == {"DB-01", "DC-01"}


def test_s2_is_stopped_by_the_mail_gateway_and_gets_through_without_it(world: World) -> None:
    assert world.run("S2").step_results[0].note.startswith("blocked by MAIL-01")

    open_mail = world.run("S2", controls=world.with_control("MAIL-01", config={"attachment_sandboxing": False}))
    assert outcomes(open_mail) == [DETECTED, UNDETECTED, DETECTED, UNDETECTED]
    assert open_mail.step_results[0].note.startswith("detected by EDR-01, not blocked")
    assert (open_mail.final_outcome, open_mail.furthest_asset_code) == (REACHED, "FS-01")


def test_s5_edr_on_the_file_server_stops_the_ransomware(world: World) -> None:
    hosts = [f"WS-{index:02d}" for index in range(1, 11)] + ["DC-01", "APP-01", "FS-01"]
    result = world.run("S5", controls=world.with_control("EDR-01", asset_codes=hosts))
    assert outcomes(result) == [DETECTED, BLOCKED]
    assert result.step_results[1].note == "blocked by EDR-01"
    assert (result.final_outcome, result.furthest_asset_code) == (PARTIAL, "FS-01")
    assert "encrypt_data" not in result.effects_gained


def test_s6_dlp_stops_or_sees_the_exfiltration(world: World) -> None:
    def with_dlp(mode: str) -> SimulationOutcome:
        dlp = make_control("DLP-01", "dlp", "network_wide", {"mode": mode, "monitored_channels": ["web"]})
        return world.run("S6", controls=[*world.controls, dlp])

    blocked = with_dlp("block")
    assert outcomes(blocked) == [DETECTED, BLOCKED]
    assert (blocked.final_outcome, blocked.effects_gained) == (PARTIAL, ["read_data"])

    detected = with_dlp("detect")
    assert outcomes(detected) == [DETECTED, DETECTED]
    assert detected.final_outcome == REACHED
    assert detected.first_detection is not None and detected.first_detection.control_code == "DLP-01"


async def test_all_six_run_through_the_stored_engine_without_errors(acme_id: str) -> None:
    for scenario in catalog.all():
        stored = await engine.run(acme_id, scenario.id)
        assert (stored.status.value, stored.error) == ("completed", None)
        assert stored.network_version == 1
        assert stored.finished_at is not None and stored.finished_at >= stored.started_at
        assert await run_repository.get_run(stored.id) == stored
    assert (await run_repository.list_runs(acme_id, 50, 0))[1] == 6
