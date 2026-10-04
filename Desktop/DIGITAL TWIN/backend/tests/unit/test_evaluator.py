"""Technique capability evaluation for every control type."""

from dataclasses import dataclass, field
from typing import Any

import pytest

from app.controls.evaluator import evaluate_all, evaluate_capability
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.enums import ControlOutcome
from app.models.evaluation import StepContext
from tests import steps
from tests.steps import make_control, make_step

Assets = dict[str, Asset]
Controls = dict[str, SecurityControl]


@dataclass
class Step:
    """A step described by technique and a path of asset codes."""

    technique: str
    path: list[str]
    port: int | None = None
    service: str | None = None

    def build(self, assets: Assets) -> StepContext:
        return make_step(assets, self.technique, self.path, port=self.port, service=self.service)


@dataclass
class Case:
    """How one control type should behave when enabled, misconfigured and out of sight."""

    control_type: str
    kind: str
    config: dict[str, Any]
    visible: Step
    outcome: str
    confidence: float
    asset_codes: list[str] = field(default_factory=list)
    zones: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    weak_config: dict[str, Any] | None = None
    missed_reason: str | None = None
    hidden: Step | None = None
    hidden_reason: str | None = None

    def control(self, assets: Assets, config: dict[str, Any] | None = None, enabled: bool = True) -> SecurityControl:
        return make_control(
            "CTRL",
            self.control_type,
            self.kind,
            config or self.config,
            assets=[assets[code] for code in self.asset_codes],
            zones=self.zones,
            services=self.services,
            enabled=enabled,
        )


SWITCH_ON = {"port_security": True, "max_macs_per_port": 2, "dhcp_snooping": True, "dynamic_arp_inspection": True}

CASES = [
    Case(
        "waf", "inline", {"mode": "block", "rulesets": []},
        Step("T1190", steps.INTERNET_TO_WEB, 443), "blocked", 0.80,
        asset_codes=["WEB-01"],
        hidden=Step("T1190", steps.WS01_TO_APP, 8080),
        hidden_reason="CTRL is not on the path and does not protect APP-01",
    ),
    Case(
        "ids_ips", "sensor", {"mode": "ips", "signature_sets": ["web"]},
        Step("T1190", steps.INTERNET_TO_WEB, 443), "blocked", 0.60,
        zones=["dmz"],
        weak_config={"mode": "ips", "signature_sets": ["network"]},
        missed_reason="signature_sets does not contain web on CTRL",
        hidden=Step("T1190", steps.WS01_TO_APP, 8080),
        hidden_reason="zone not watched: CTRL has no sensor in corporate or server",
    ),
    Case(
        "nac_8021x", "inline", {"enforced": True, "mac_auth_bypass_allowed": False},
        Step("T1599", steps.GUEST_TO_AP), "blocked", 0.90,
        asset_codes=["AP-01"],
        weak_config={"enforced": True, "mac_auth_bypass_allowed": True},
        missed_reason="mac_auth_bypass_allowed is true on CTRL",
        hidden=Step("T1599", steps.WS01_TO_WS02),
        hidden_reason="not on the path",
    ),
    Case(
        "switch_security", "inline", SWITCH_ON,
        Step("T1557.002", steps.WS01_TO_WS02), "blocked", 0.90,
        asset_codes=["SW-ACCESS-1"],
        weak_config={**SWITCH_ON, "dynamic_arp_inspection": False},
        missed_reason="dynamic_arp_inspection is false on CTRL",
        hidden=Step("T1557.002", steps.WS06_TO_WS07),
        hidden_reason="not on the path",
    ),
    Case(
        "mfa", "identity", {"enforced_for": ["vpn"]},
        Step("T1133", steps.INTERNET_TO_VPN, 443, "vpn"), "blocked", 0.90,
        services=["vpn"],
        hidden=Step("T1078", steps.INTERNET_TO_WS01, service="email"),
        hidden_reason="service email is not protected by CTRL",
    ),
    Case(
        "identity_policy", "identity", {"lockout_threshold": 5, "password_min_length": 12},
        Step("T1110", steps.INTERNET_TO_VPN, 443, "vpn"), "blocked", 0.70,
        services=["vpn"],
        weak_config={"lockout_threshold": None, "password_min_length": 12},
        missed_reason="lockout_threshold is not set on CTRL",
        hidden=Step("T1110", steps.WS01_TO_FS, 445, "ad"),
        hidden_reason="service ad is not protected by CTRL",
    ),
    Case(
        "edr", "host", {"mode": "block"},
        Step("T1003", ["DC-01"]), "blocked", 0.85,
        asset_codes=["DC-01"],
        hidden=Step("T1486", ["FS-01"]),
        hidden_reason="CTRL is not installed on FS-01",
    ),
    Case(
        "email_gateway", "identity", {"attachment_sandboxing": True, "url_rewriting": False},
        Step("T1566.001", steps.INTERNET_TO_WS01, service="email"), "blocked", 0.70,
        services=["email"],
        weak_config={"attachment_sandboxing": False, "url_rewriting": True},
        missed_reason="attachment_sandboxing is false on CTRL",
        hidden=Step("T1566.001", steps.INTERNET_TO_WS01),
        hidden_reason="step has no service",
    ),
    Case(
        "dlp", "sensor", {"mode": "block", "monitored_channels": ["web"]},
        Step("T1048", steps.DB_TO_INTERNET, 443), "blocked", 0.70,
        zones=["server"],
        hidden=Step("T1048", ["WS-01", "SW-ACCESS-1", "WS-02"], 443),
        hidden_reason="zone not watched",
    ),
    Case(
        "siem", "network_wide", {"log_sources": ["auth"], "ueba": False},
        Step("T1110", steps.INTERNET_TO_VPN, 443, "vpn"), "detected", 0.80,
        weak_config={"log_sources": ["firewall"], "ueba": False},
        missed_reason="log_sources does not contain auth on CTRL",
    ),
    Case(
        "firewall", "inline", {"rules": [], "default_action": "allow", "logging": True},
        Step("T1046", steps.WEB_TO_APP, 8080), "logged", 0.50,
        asset_codes=["FW-EDGE"],
        weak_config={"rules": [], "default_action": "allow", "logging": False},
        missed_reason="logging is false on CTRL",
        hidden=Step("T1046", steps.WS01_TO_APP, 8080),
        hidden_reason="not on the path",
    ),
    Case(
        "honeypot", "sensor", {"decoy_services": ["smb", "ssh"], "alerting": True},
        Step("T1046", steps.WS01_TO_APP, 8080), "detected", 0.85,
        zones=["server"],
        weak_config={"decoy_services": ["smb"], "alerting": False},
        missed_reason="alerting is false on CTRL",
        hidden=Step("T1046", steps.INTERNET_TO_WEB, 443),
        hidden_reason="zone not watched",
    ),
    Case(
        "segmentation", "network_wide", {"vlan_rules": [], "default_action": "allow"},
        Step("T1046", steps.WEB_TO_APP, 8080), "not_applicable", 0.0,
    ),
    Case(
        "backup", "host", {"offline_copies": True, "tested_restore": True},
        Step("T1486", ["FS-01"]), "not_applicable", 0.0,
        asset_codes=["FS-01"],
        hidden=Step("T1486", ["DB-01"]),
        hidden_reason="CTRL is not installed on DB-01",
    ),
]
CASE_IDS = [case.control_type for case in CASES]


def test_cases_cover_all_14_types() -> None:
    assert len(set(CASE_IDS)) == 14


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_enabled_control(case: Case, acme_assets: Assets) -> None:
    control = case.control(acme_assets)
    result = evaluate_capability(control, case.visible.build(acme_assets))
    assert result.outcome.value == case.outcome
    assert result.confidence == case.confidence
    assert (result.control_id, result.control_code) == (control.id, "CTRL")
    if case.outcome == "not_applicable":
        assert f"{case.control_type} has no capability for {case.visible.technique}" == result.reason


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_disabled_control(case: Case, acme_assets: Assets) -> None:
    result = evaluate_capability(case.control(acme_assets, enabled=False), case.visible.build(acme_assets))
    assert (result.outcome, result.confidence, result.reason) == (
        ControlOutcome.NOT_APPLICABLE,
        0.0,
        "control disabled",
    )


@pytest.mark.parametrize("case", [c for c in CASES if c.weak_config], ids=lambda c: c.control_type)
def test_missed_requirement(case: Case, acme_assets: Assets) -> None:
    control = case.control(acme_assets, config=case.weak_config)
    result = evaluate_capability(control, case.visible.build(acme_assets))
    assert result.outcome == ControlOutcome.MISSED
    assert result.confidence == 0.0
    assert result.reason == case.missed_reason


@pytest.mark.parametrize("case", [c for c in CASES if c.hidden], ids=lambda c: c.control_type)
def test_control_that_cannot_see_the_step(case: Case, acme_assets: Assets) -> None:
    assert case.hidden is not None and case.hidden_reason is not None
    result = evaluate_capability(case.control(acme_assets), case.hidden.build(acme_assets))
    assert result.outcome == ControlOutcome.NOT_APPLICABLE
    assert case.hidden_reason in result.reason


def test_placement_is_checked_before_requirements(acme_assets: Assets) -> None:
    weak_and_hidden = make_control(
        "SW", "switch_security", "inline", {**SWITCH_ON, "dynamic_arp_inspection": False},
        assets=[acme_assets["SW-ACCESS-1"]],
    )
    result = evaluate_capability(weak_and_hidden, make_step(acme_assets, "T1557.002", steps.WS06_TO_WS07))
    assert result.outcome == ControlOutcome.NOT_APPLICABLE


def test_firewall_and_waf_are_not_applicable_for_arp_poisoning(
    acme_assets: Assets, acme_controls: Controls
) -> None:
    through_core = make_step(acme_assets, "T1557.002", steps.WS01_TO_WS06)
    firewall = evaluate_capability(acme_controls["FW-INT"], through_core)
    assert firewall.outcome == ControlOutcome.NOT_APPLICABLE
    assert firewall.reason == "T1557.002 works at layer 2, below layer 3 where firewall operates"

    at_web = make_step(acme_assets, "T1557.002", ["FW-EDGE", "WEB-01"])
    waf = evaluate_capability(acme_controls["WAF-01"], at_web)
    assert waf.outcome == ControlOutcome.NOT_APPLICABLE
    assert waf.reason == "T1557.002 works at layer 2, below layer 7 where waf operates"

    edge = evaluate_capability(acme_controls["FW-EDGE"], at_web)
    assert edge.outcome == ControlOutcome.NOT_APPLICABLE

    bridging = make_step(acme_assets, "T1599", ["FW-EDGE", "WEB-01"])
    for code in ("FW-EDGE", "WAF-01", "SEG-01"):
        assert evaluate_capability(acme_controls[code], bridging).outcome == ControlOutcome.NOT_APPLICABLE


def test_dynamic_arp_inspection_gap_on_floor_2(acme_assets: Assets, acme_controls: Controls) -> None:
    floor_2 = make_step(acme_assets, "T1557.002", steps.WS06_TO_WS07)
    missed = evaluate_capability(acme_controls["SWSEC-2"], floor_2)
    assert missed.outcome == ControlOutcome.MISSED
    assert missed.reason == "dynamic_arp_inspection is false on SWSEC-2"

    floor_1 = make_step(acme_assets, "T1557.002", steps.WS01_TO_WS02)
    blocked = evaluate_capability(acme_controls["SWSEC-1"], floor_1)
    assert (blocked.outcome, blocked.confidence) == (ControlOutcome.BLOCKED, 0.90)

    fixed_config = acme_controls["SWSEC-2"].config.model_copy(update={"dynamic_arp_inspection": True})
    fixed = acme_controls["SWSEC-2"].model_copy(update={"config": fixed_config})
    assert evaluate_capability(fixed, floor_2).outcome == ControlOutcome.BLOCKED


def test_waf_in_detect_mode_detects_but_does_not_block(
    acme_assets: Assets, acme_controls: Controls
) -> None:
    step = make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443)
    result = evaluate_capability(acme_controls["WAF-01"], step)
    assert (result.outcome, result.confidence) == (ControlOutcome.DETECTED, 0.80)
    assert result.reason == "WAF-01 detects T1190 (would block, but mode is detect)"


def test_mfa_does_not_cover_vpn_until_vpn_is_added(
    acme_assets: Assets, acme_controls: Controls
) -> None:
    vpn_login = make_step(acme_assets, "T1133", steps.INTERNET_TO_VPN, port=443, service="vpn")
    mfa = acme_controls["MFA-01"]
    before = evaluate_capability(mfa, vpn_login)
    assert before.outcome == ControlOutcome.NOT_APPLICABLE
    assert before.reason == "service vpn is not protected by MFA-01"

    placement = mfa.placement.model_copy(update={"services": ["email", "ad", "vpn"]})
    placement_only = mfa.model_copy(update={"placement": placement})
    half = evaluate_capability(placement_only, vpn_login)
    assert half.outcome == ControlOutcome.NOT_APPLICABLE
    assert half.reason == "service vpn is not in enforced_for of MFA-01"

    config = mfa.config.model_copy(update={"enforced_for": ["email", "ad", "vpn"]})
    after = evaluate_capability(placement_only.model_copy(update={"config": config}), vpn_login)
    assert (after.outcome, after.confidence) == (ControlOutcome.BLOCKED, 0.90)


def test_edr_gap_on_file_server(acme_assets: Assets, acme_controls: Controls) -> None:
    edr = acme_controls["EDR-01"]
    on_file_server = evaluate_capability(edr, make_step(acme_assets, "T1486", ["FS-01"]))
    assert on_file_server.outcome == ControlOutcome.NOT_APPLICABLE
    assert on_file_server.reason == "EDR-01 is not installed on FS-01"

    on_workstation = evaluate_capability(edr, make_step(acme_assets, "T1486", ["WS-03"]))
    assert (on_workstation.outcome, on_workstation.confidence) == (ControlOutcome.BLOCKED, 0.80)


def test_ids_only_watches_dmz_and_server_zones(acme_assets: Assets, acme_controls: Controls) -> None:
    ids = acme_controls["IDS-01"]
    lateral = evaluate_capability(ids, make_step(acme_assets, "T1021.002", steps.WS06_TO_WS07, port=445))
    assert lateral.outcome == ControlOutcome.NOT_APPLICABLE
    assert "zone not watched" in lateral.reason

    to_server = evaluate_capability(ids, make_step(acme_assets, "T1021.002", steps.WS01_TO_FS, port=445))
    assert (to_server.outcome, to_server.confidence) == (ControlOutcome.DETECTED, 0.55)

    web = evaluate_capability(ids, make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443))
    assert web.outcome == ControlOutcome.DETECTED


def test_evaluate_all_is_sorted_and_complete(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1110", steps.INTERNET_TO_VPN, port=443, service="vpn")
    results = evaluate_all(list(acme_controls.values()), step)

    assert len(results) == 14
    summary = [(item.control_code, item.outcome.value) for item in results if item.outcome != ControlOutcome.NOT_APPLICABLE]
    assert summary == [("SIEM-01", "detected"), ("IDP-01", "missed"), ("IDS-01", "missed")]
    order = [item.outcome.value for item in results]
    ranks = {"blocked": 0, "detected": 1, "logged": 2, "missed": 3, "not_applicable": 4}
    assert [ranks[value] for value in order] == sorted(ranks[value] for value in order)
    not_applicable = [item.control_code for item in results if item.outcome == ControlOutcome.NOT_APPLICABLE]
    assert not_applicable == sorted(not_applicable)


def test_evaluate_all_orders_by_outcome_then_confidence(acme_assets: Assets) -> None:
    web = [acme_assets["WEB-01"]]
    controls = [
        make_control("A-DETECT", "waf", "inline", {"mode": "detect", "rulesets": []}, assets=web),
        make_control("B-BLOCK-60", "ids_ips", "sensor", {"mode": "ips", "signature_sets": ["web"]}, zones=["dmz"]),
        make_control("C-BLOCK-80", "waf", "inline", {"mode": "block", "rulesets": []}, assets=web),
        make_control("D-MISSED", "ids_ips", "sensor", {"mode": "ips", "signature_sets": []}, zones=["dmz"]),
        make_control("E-LOG", "edr", "host", {"mode": "block"}, assets=web),
    ]
    step = make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443)
    assert [(item.control_code, item.outcome.value) for item in evaluate_all(controls, step)] == [
        ("C-BLOCK-80", "blocked"),
        ("B-BLOCK-60", "blocked"),
        ("A-DETECT", "detected"),
        ("D-MISSED", "missed"),
        ("E-LOG", "not_applicable"),
    ]
