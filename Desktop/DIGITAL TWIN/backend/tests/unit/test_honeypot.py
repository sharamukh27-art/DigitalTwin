"""Honeypot control type: a detect-only sensor for scanning and lateral movement inside a zone."""

from app.controls import catalog
from app.controls.coverage import build_coverage
from app.controls.evaluator import evaluate_all, evaluate_capability
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.enums import CapabilityAction, ControlOutcome, ControlType
from tests import steps
from tests.sim import World, load_world
from tests.steps import make_control, make_step

Assets = dict[str, Asset]
Controls = dict[str, SecurityControl]


def honeypot(zones: list[str], decoys: list[str] | None = None, alerting: bool = True) -> SecurityControl:
    return make_control(
        "HONEY-01", "honeypot", "sensor",
        {"decoy_services": ["smb", "ssh"] if decoys is None else decoys, "alerting": alerting},
        zones=zones,
    )


def test_a_honeypot_never_blocks() -> None:
    capabilities = catalog.capabilities_for(ControlType.HONEYPOT)
    assert set(capabilities) == {"T1046", "T1021.002", "T1110"}
    assert all(capability.action == CapabilityAction.DETECT for capability in capabilities.values())


def test_it_sees_lateral_movement_where_the_ids_is_blind(acme_assets: Assets, acme_controls: Controls) -> None:
    same_floor = make_step(acme_assets, "T1021.002", steps.WS06_TO_WS07, port=445)
    assert evaluate_capability(acme_controls["IDS-01"], same_floor).outcome == ControlOutcome.NOT_APPLICABLE

    result = evaluate_capability(honeypot(["corporate"]), same_floor)
    assert (result.outcome, result.confidence, result.reason) == (ControlOutcome.DETECTED, 0.45, "HONEY-01 detects T1021.002")

    everything = evaluate_all([*acme_controls.values(), honeypot(["corporate"])], same_floor)
    assert [(item.control_code, item.outcome.value) for item in everything[:2]] == [("EDR-01", "detected"), ("HONEY-01", "detected")]


def test_it_detects_scans_and_brute_force(acme_assets: Assets) -> None:
    decoys = honeypot(["server"])
    scan = evaluate_capability(decoys, make_step(acme_assets, "T1046", steps.WS01_TO_APP, port=8080))
    assert (scan.outcome, scan.confidence) == (ControlOutcome.DETECTED, 0.85)
    brute = evaluate_capability(honeypot(["dmz"]), make_step(acme_assets, "T1110", steps.INTERNET_TO_VPN, port=443, service="vpn"))
    assert (brute.outcome, brute.confidence) == (ControlOutcome.DETECTED, 0.40)


def test_requirements_and_visibility(acme_assets: Assets) -> None:
    lateral = make_step(acme_assets, "T1021.002", steps.WS06_TO_WS07, port=445)

    silent = evaluate_capability(honeypot(["corporate"], alerting=False), lateral)
    assert (silent.outcome, silent.reason) == (ControlOutcome.MISSED, "alerting is false on HONEY-01")

    no_smb = evaluate_capability(honeypot(["corporate"], decoys=["ssh"]), lateral)
    assert (no_smb.outcome, no_smb.reason) == (ControlOutcome.MISSED, "decoy_services does not contain smb on HONEY-01")

    elsewhere = evaluate_capability(honeypot(["dmz"]), lateral)
    assert elsewhere.outcome == ControlOutcome.NOT_APPLICABLE and "zone not watched" in elsewhere.reason

    arp = evaluate_capability(honeypot(["corporate"]), make_step(acme_assets, "T1557.002", steps.WS06_TO_WS07))
    assert arp.outcome == ControlOutcome.NOT_APPLICABLE
    assert arp.reason == "T1557.002 works at layer 2, below layer 4 where honeypot operates"

    exploit = evaluate_capability(honeypot(["dmz"]), make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443))
    assert exploit.reason == "honeypot has no capability for T1190"


def test_coverage_lists_the_honeypot_column(acme_assets: Assets, acme_controls: Controls) -> None:
    result = build_coverage([*acme_controls.values(), honeypot(["server"])], list(acme_assets.values()))
    scan = next(row for row in result.matrix if row.technique_id == "T1046")
    cell = next(item for item in scan.cells if item.control_code == "HONEY-01")
    assert (cell.action.value, cell.status.value, cell.confidence) == ("detect", "active", 0.85)
    assert result.coverage_percent == 85.7
    sensor_gaps = {(gap.control_type.value, gap.zone.value) for gap in result.placement_gaps if gap.zone}
    assert ("honeypot", "corporate") in sensor_gaps and ("honeypot", "server") not in sensor_gaps


async def test_the_sample_network_is_unchanged(acme_id: str) -> None:
    world: World = await load_world(acme_id)
    assert all(control.type != ControlType.HONEYPOT for control in world.controls)
    assert len(world.controls) == 14


async def test_a_honeypot_in_the_server_zone_adds_detection_to_s5(acme_id: str) -> None:
    world: World = await load_world(acme_id)
    before = world.run("S5")
    after = world.run("S5", controls=[*world.controls, honeypot(["server"])])
    assert [step.outcome for step in after.step_results] == [step.outcome for step in before.step_results]
    first = {item.control_code: item.outcome.value for item in after.step_results[0].control_results}
    assert first["HONEY-01"] == "detected"
    assert after.final_outcome == before.final_outcome
