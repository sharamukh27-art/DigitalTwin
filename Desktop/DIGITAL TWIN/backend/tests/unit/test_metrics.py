"""Findings and weakest link, on the ACME sample and on small hand-built cases."""

import pytest
import pytest_asyncio

from app.analysis import metrics, service
from app.analysis import repository as findings_repository
from app.analysis.weakest_link import Candidate, collect_candidates, find_weakest_link, rank
from app.core.errors import ValidationFailed
from app.models.analysis import Findings, TwinSnapshot, WeakestLink
from app.models.enums import WeakestLinkKind
from app.models.network import Network
from app.simulation import engine
from app.twin import repository
from tests.sim import World, load_world, make_asset, make_link, make_scenario, make_world, step
from tests.steps import make_control


@pytest_asyncio.fixture
async def world(acme_id: str) -> World:
    return await load_world(acme_id)


async def findings_of(network_id: str, code: str) -> Findings:
    run = await engine.run(network_id, code)
    return await service.findings_for_run(run.id)


def weakest(world: World, code: str, controls: list | None = None) -> WeakestLink | None:
    used = world.controls if controls is None else controls
    outcome = world.run(code, controls=used)
    return find_weakest_link(
        outcome.step_results,
        {control.code: control for control in used},
        {asset.code: asset for asset in world.assets},
    )


async def test_s1_findings(acme_id: str) -> None:
    findings = await findings_of(acme_id, "S1")
    assert (findings.scenario_code, findings.network_version) == ("S1", 1)
    assert findings.attacker_profile.value == "compromised_device"
    assert findings.containment.value == "objective_reached"
    assert findings.first_detection_step == 1
    assert findings.time_to_detect_seconds is not None and findings.time_to_detect_seconds > 0
    assert findings.first_block_step is None
    assert [item.code for item in findings.detecting_controls] == ["NAC-01", "SWSEC-2", "IDS-01", "FW-INT"]
    assert findings.detecting_controls[0].name == "802.1X network access control"
    assert findings.blocking_controls == []
    assert [(item.code, item.step_order, item.technique_id) for item in findings.missed_controls] == [
        ("SWSEC-2", 1, "T1557.002"), ("NAC-01", 2, "T1599"), ("SIEM-01", 5, "T1078"),
    ]
    assert findings.missed_controls[0].reason == "dynamic_arp_inspection is false on SWSEC-2"
    assert findings.not_seen_gaps == []
    assert findings.attack_depth.model_dump() == {"hops_achieved": 5, "total_steps": 5, "ratio": 1.0}
    assert [item.outcome.value for item in findings.killchain] == [
        "detected_not_blocked", "detected_not_blocked", "detected_not_blocked", "detected_not_blocked", "undetected",
    ]
    assert [item.tactic.value for item in findings.killchain][:3] == ["credential_access", "defense_evasion", "discovery"]
    assert findings.effects_gained == ["obtain_credentials", "gain_foothold", "escalate_privilege", "read_data"]
    assert findings.total_network_criticality == 72
    assert findings.unrecoverable_encryption is False

    blast = findings.blast_radius
    assert blast.asset_codes[0] == "SW-ACCESS-2" and blast.asset_codes[-1] == "APP-01"
    assert "DB-01" in blast.asset_codes and "GUEST-DEV" not in blast.asset_codes
    assert (blast.count, blast.max_criticality, blast.criticality_sum) == (4, 5, 14)
    assert sorted(blast.data_assets_reached) == ["APP-01", "DB-01"]
    assert (blast.max_cvss, blast.max_data_classification.value) == (0.0, "restricted")

    link = findings.weakest_link
    assert link is not None
    assert (link.kind.value, link.ref, link.step_order) == ("missed_control", "SWSEC-2", 1)
    assert "dynamic_arp_inspection is false on SWSEC-2" in link.explanation
    assert "would have blocked it" in link.explanation


async def test_contained_run_has_empty_blast_radius_and_no_weakest_link(acme_id: str) -> None:
    findings = await findings_of(acme_id, "S2")
    assert findings.containment.value == "contained"
    assert (findings.first_detection_step, findings.first_block_step) == (1, 1)
    assert [item.code for item in findings.blocking_controls] == ["MAIL-01"]
    assert findings.attack_depth.model_dump() == {"hops_achieved": 0, "total_steps": 4, "ratio": 0.0}
    assert findings.blast_radius.model_dump() == {
        "asset_codes": [], "count": 0, "criticality_sum": 0, "max_criticality": 0,
        "data_assets_reached": [], "max_cvss": 0.0, "max_data_classification": None,
    }
    assert findings.weakest_link is None
    assert len(findings.killchain) == 1


async def test_blind_spots_name_the_controls_that_could_not_see(acme_id: str) -> None:
    vpn = await findings_of(acme_id, "S4")
    assert [(gap.step_order, gap.technique_id) for gap in vpn.not_seen_gaps] == [(1, "T1133")]
    assert vpn.not_seen_gaps[0].note == (
        "No control was applicable to T1133 against VPN-01. Controls with the capability that "
        "could not see it: MFA-01: service vpn is not protected by MFA-01."
    )
    assert (vpn.weakest_link.kind.value, vpn.weakest_link.ref, vpn.weakest_link.step_order) == ("blind_spot", "T1133", 1)

    ransomware = await findings_of(acme_id, "S5")
    assert [(gap.step_order, gap.technique_id) for gap in ransomware.not_seen_gaps] == [(2, "T1003"), (3, "T1486")]
    assert "EDR-01: EDR-01 is not installed on FS-01" in ransomware.not_seen_gaps[0].note
    assert (ransomware.weakest_link.kind.value, ransomware.weakest_link.step_order) == ("blind_spot", 2)
    assert ransomware.unrecoverable_encryption is True
    assert ransomware.blast_radius.asset_codes == ["FS-01"]
    assert ransomware.blast_radius.max_cvss == 8.8


async def test_never_detected_run_and_attacker_node_is_not_in_the_blast_radius(acme_id: str) -> None:
    findings = await findings_of(acme_id, "S6")
    assert findings.first_detection_step is None and findings.time_to_detect_seconds is None
    assert findings.detecting_controls == []
    assert findings.blast_radius.asset_codes == ["FS-01"]
    assert findings.blast_radius.data_assets_reached == ["FS-01"]
    assert "exfiltrate_data" in findings.effects_gained
    assert len(findings.not_seen_gaps) == 2


async def test_every_scenario_has_findings_and_they_are_cached(acme_id: str) -> None:
    for code in ("S1", "S2", "S3", "S4", "S5", "S6"):
        run = await engine.run(acme_id, code)
        first = await service.findings_for_run(run.id)
        assert first.run_id == run.id
        assert first.blast_radius.count == len(first.blast_radius.asset_codes)
        assert (first.weakest_link is None) == (code == "S2")
        second = await service.findings_for_run(run.id)
        assert second == first
        assert (await findings_repository.get_findings(run.id)) == first


async def test_failed_run_has_no_findings(database: object) -> None:
    network = await repository.insert_network(Network(name="empty"))
    failed = await engine.run(network.id, "S1")
    with pytest.raises(ValidationFailed, match="has status failed"):
        await service.findings_for_run(failed.id)
    with pytest.raises(ValueError, match="did not complete"):
        metrics.compute_findings(failed, TwinSnapshot(network=network, assets=[], controls=[]))


def test_offline_backup_makes_encryption_recoverable(world: World) -> None:
    file_server = world.asset("FS-01")
    assert metrics.has_offline_backup(file_server, world.controls) is False
    offline = world.with_control("BKP-01", config={"offline_copies": True})
    assert metrics.has_offline_backup(file_server, offline) is True
    assert metrics.has_offline_backup(world.asset("DC-01"), offline) is False
    disabled = [c.model_copy(update={"enabled": False}) if c.code == "BKP-01" else c for c in offline]
    assert metrics.has_offline_backup(file_server, disabled) is False


def test_weakest_link_on_the_sample(world: World) -> None:
    assert weakest(world, "S1").ref == "SWSEC-2"
    assert weakest(world, "S2") is None

    hardened = world.with_control("SWSEC-2", config={"dynamic_arp_inspection": True})
    assert weakest(world, "S1", hardened) is None

    nac_fixed = world.with_control("NAC-01", config={"mac_auth_bypass_allowed": False})
    link = weakest(world, "S1", nac_fixed)
    assert (link.ref, link.step_order) == ("SWSEC-2", 1)


def test_downgraded_block_counts_and_lowest_confidence_wins_a_tie(world: World) -> None:
    link = weakest(world, "S3")
    assert (link.kind, link.ref, link.step_order) == (WeakestLinkKind.MISSED_CONTROL, "IDS-01", 1)
    assert link.explanation == (
        "IDS-01 saw step 1 (T1190 against WEB-01) but runs in ids mode, so it did not block it."
    )

    prevention = world.with_control("IDS-01", config={"mode": "ips"})
    assert weakest(world, "S3", prevention) is None

    only_waf = world.with_control("IDS-01", enabled=False)
    link = weakest(world, "S3", only_waf)
    assert (link.ref, link.step_order) == ("WAF-01", 1)
    assert "runs in detect mode" in link.explanation


def test_detect_only_miss_loses_to_a_later_failure_that_reaches_further(world: World) -> None:
    world.controls = world.with_control("WAF-01", enabled=False)
    controls = world.with_control("IDS-01", config={"signature_sets": ["network", "smb"]})
    outcome = world.run("S3", controls=controls)
    candidates = collect_candidates(
        outcome.step_results,
        {control.code: control for control in controls},
        {asset.code: asset for asset in world.assets},
    )
    first_step = [item for item in candidates if item.step_order == 1]
    assert [(item.ref, item.reach) for item in first_step] == [("IDS-01", 0)]
    assert "would only detect it" in first_step[0].explanation

    link = weakest(world, "S3", controls)
    assert (link.kind, link.ref, link.step_order) == (WeakestLinkKind.BLIND_SPOT, "T1505.003", 2)


def test_connectivity_hole_is_reported_when_nothing_filters_a_zone_crossing() -> None:
    world = make_world(
        [make_asset("A", "workstation", "corporate"), make_asset("B", "server", "server")],
        [make_link("L1", "A", "B")],
    )
    scenario = make_scenario([step(1, target_code="B", port=80, on_success=["gain_foothold"])])
    assets = {asset.code: asset for asset in world.assets}
    steps = world.run(scenario).step_results

    candidates = rank(collect_candidates(steps, {}, assets))
    assert [(item.kind.value, item.ref, item.reach) for item in candidates] == [
        ("connectivity_hole", "A->B", 1),
        ("blind_spot", "T1190", 1),
    ]
    link = find_weakest_link(steps, {}, assets)
    assert link.kind == WeakestLinkKind.CONNECTIVITY_HOLE
    assert "traffic from corporate to server was not filtered" in link.explanation

    firewall = make_control(
        "FW", "firewall", "inline", {"rules": [], "default_action": "allow", "logging": False},
        assets=[world.asset("B")],
    )
    filtered = find_weakest_link(world.run(scenario, controls=[firewall]).step_results, {"FW": firewall}, assets)
    assert filtered.kind == WeakestLinkKind.BLIND_SPOT


def test_rank_order() -> None:
    def candidate(ref: str, step_order: int, reach: int, confidence: float, kind: str = "missed_control") -> Candidate:
        return Candidate(WeakestLinkKind(kind), ref, step_order, reach, confidence, "")

    ranked = rank(
        [
            candidate("late-far", 3, 4, 0.9),
            candidate("early-near", 1, 2, 0.1),
            candidate("early-far-strong", 2, 5, 0.9),
            candidate("early-far-weak", 2, 5, 0.4),
            candidate("earliest-far", 1, 5, 0.95),
            candidate("blind", 1, 5, 0.95, "blind_spot"),
        ]
    )
    assert [item.ref for item in ranked] == [
        "earliest-far", "blind", "early-far-weak", "early-far-strong", "late-far", "early-near",
    ]
    assert rank([]) == []
