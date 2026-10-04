"""Coverage matrix and the gaps planted in the ACME sample."""

from typing import Any

import pytest

from app.controls.coverage import build_coverage, coverage
from app.core.errors import NotFound
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.evaluation import CoverageCell, CoverageResponse
from app.twin import techniques
from tests.steps import make_control

Assets = dict[str, Asset]
Controls = dict[str, SecurityControl]


def cell(result: CoverageResponse, technique_id: str, control_code: str) -> CoverageCell:
    row = next(row for row in result.matrix if row.technique_id == technique_id)
    return next(item for item in row.cells if item.control_code == control_code)


async def test_matrix_shape(acme_id: str) -> None:
    result = await coverage(acme_id)
    assert [row.technique_id for row in result.matrix] == [item.id for item in techniques.all()]
    for row in result.matrix:
        assert len(row.cells) == 14
        assert [item.control_code for item in row.cells] == sorted(item.control_code for item in row.cells)
    first = result.matrix[0]
    assert (first.technique_name, first.tactic.value) == ("ARP Cache Poisoning", "credential_access")


async def test_coverage_percent_is_stable(acme_id: str) -> None:
    first = await coverage(acme_id)
    second = await coverage(acme_id)
    assert first == second
    assert first.coverage_percent == 85.7
    assert first.uncovered_techniques == ["T1133"]
    assert first.weakly_covered == ["T1005"]


async def test_gap_1_waf_only_detects(acme_id: str) -> None:
    waf = cell(await coverage(acme_id), "T1190", "WAF-01")
    assert (waf.action.value, waf.status.value, waf.confidence) == ("detect", "active", 0.80)
    assert waf.downgraded_from is not None and waf.downgraded_from.value == "block"


async def test_gap_2_nac_allows_mac_auth_bypass(acme_id: str) -> None:
    nac = cell(await coverage(acme_id), "T1599", "NAC-01")
    assert nac.status.value == "missed_requirement"
    assert nac.reason == "mac_auth_bypass_allowed is true on NAC-01"


async def test_gap_3_no_dynamic_arp_inspection_on_floor_2(acme_id: str) -> None:
    result = await coverage(acme_id)
    weak = cell(result, "T1557.002", "SWSEC-2")
    assert weak.status.value == "missed_requirement"
    assert weak.reason == "dynamic_arp_inspection is false on SWSEC-2"
    strong = cell(result, "T1557.002", "SWSEC-1")
    assert (strong.action.value, strong.status.value, strong.confidence) == ("block", "active", 0.90)


async def test_gap_4_mfa_does_not_cover_vpn(acme_id: str) -> None:
    result = await coverage(acme_id)
    mfa = cell(result, "T1133", "MFA-01")
    assert mfa.status.value == "missed_requirement"
    assert mfa.reason == "enforced_for does not contain vpn on MFA-01"
    assert "T1133" in result.uncovered_techniques


async def test_gap_5_file_server_has_no_edr(acme_id: str) -> None:
    result = await coverage(acme_id)
    host_gaps = {gap.asset_code: gap for gap in result.placement_gaps if gap.kind.value == "host"}
    assert sorted(host_gaps) == ["ADMIN-01", "DB-01", "FS-01"]
    assert host_gaps["FS-01"].control_type.value == "edr"
    assert host_gaps["FS-01"].reason == "FS-01 (criticality 4) has no edr"
    assert cell(result, "T1486", "EDR-01").status.value == "active"


async def test_sensor_gaps_list_unwatched_zones(acme_id: str) -> None:
    result = await coverage(acme_id)
    zones = [gap.zone.value for gap in result.placement_gaps if gap.kind.value == "sensor" and gap.zone]
    assert zones == ["guest", "corporate", "management"]


async def test_other_cells(acme_id: str) -> None:
    result = await coverage(acme_id)
    assert cell(result, "T1046", "FW-EDGE").action.value == "log"
    assert cell(result, "T1110", "IDP-01").reason == "lockout_threshold is not set on IDP-01"
    assert cell(result, "T1078", "SIEM-01").reason == "ueba is false on SIEM-01"
    backup = cell(result, "T1486", "BKP-01")
    assert (backup.action, backup.status.value, backup.confidence) == (None, "none", 0.0)


async def test_fixing_gaps_raises_coverage(acme_assets: Assets, acme_controls: Controls) -> None:
    mfa = acme_controls["MFA-01"]
    fixed_mfa = mfa.model_copy(
        update={"config": mfa.config.model_copy(update={"enforced_for": ["email", "ad", "vpn"]})}
    )
    controls = [fixed_mfa if control.code == "MFA-01" else control for control in acme_controls.values()]
    controls.append(make_control("DLP-01", "dlp", "network_wide", {"mode": "block", "monitored_channels": []}))

    result = build_coverage(controls, list(acme_assets.values()))
    assert result.coverage_percent == 100.0
    assert result.uncovered_techniques == []
    assert result.weakly_covered == []


def test_disabled_controls_do_not_count(acme_assets: Assets) -> None:
    def edr(enabled: bool) -> list[SecurityControl]:
        return [make_control("EDR", "edr", "host", {"mode": "block"}, assets=[acme_assets["DC-01"]], enabled=enabled)]

    enabled = build_coverage(edr(True), list(acme_assets.values()))
    disabled = build_coverage(edr(False), list(acme_assets.values()))

    assert enabled.coverage_percent == pytest.approx(35.7)
    assert "T1005" in enabled.weakly_covered
    assert disabled.coverage_percent == 0.0
    assert len(disabled.uncovered_techniques) == 14
    assert cell(disabled, "T1003", "EDR").reason == "control disabled"
    assert disabled.placement_gaps == []


def test_log_only_coverage_counts_as_uncovered(acme_assets: Assets) -> None:
    firewall = make_control(
        "FW", "firewall", "inline", {"rules": [], "default_action": "deny", "logging": True},
        assets=[acme_assets["FW-EDGE"]],
    )
    result = build_coverage([firewall], list(acme_assets.values()))
    assert "T1046" in result.uncovered_techniques
    assert result.coverage_percent == 0.0


async def test_network_without_controls(database: Any) -> None:
    from app.models.network import Network
    from app.twin import repository

    network = await repository.insert_network(Network(name="bare"))
    result = await coverage(network.id)
    assert result.coverage_percent == 0.0
    assert len(result.uncovered_techniques) == 14
    assert all(row.cells == [] for row in result.matrix)


async def test_unknown_network_raises_not_found(database: Any) -> None:
    with pytest.raises(NotFound):
        await coverage("missing")
