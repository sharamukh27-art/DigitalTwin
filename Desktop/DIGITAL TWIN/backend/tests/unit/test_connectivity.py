"""Connectivity enforcement: firewall rules and VLAN segmentation."""

from typing import Any

from app.controls.connectivity import check_connectivity
from app.models.asset import Asset
from app.models.control import SecurityControl
from tests import steps
from tests.steps import make_control, make_step

Assets = dict[str, Asset]
Controls = dict[str, SecurityControl]


def rule(src: str, dst: str, action: str, ports: tuple[int, ...] = (), protocol: str = "any") -> dict[str, Any]:
    return {"src_zone": src, "dst_zone": dst, "ports": list(ports), "protocol": protocol, "action": action}


def test_internet_to_database_is_denied_by_edge_firewall(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1190", steps.INTERNET_TO_DB, port=5432, protocol="tcp")
    result = check_connectivity(list(acme_controls.values()), step)
    assert result.allowed is False
    assert result.deciding_control_id == acme_controls["FW-EDGE"].id
    assert result.rule_index is None
    assert "FW-EDGE has no rule for internet -> server port 5432" in result.reason


def test_internet_to_web_443_is_allowed(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443, protocol="tcp")
    result = check_connectivity(list(acme_controls.values()), step)
    assert result.allowed is True
    assert result.deciding_control_id == acme_controls["FW-EDGE"].id
    assert result.rule_index == 0
    assert result.reason == "FW-EDGE rule 0 allows internet -> dmz port 443"


def test_internet_to_web_ssh_is_denied(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1110", steps.INTERNET_TO_WEB, port=22, protocol="tcp")
    assert check_connectivity(list(acme_controls.values()), step).allowed is False


def test_every_firewall_on_the_path_must_allow(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1046", steps.WEB_TO_APP, port=8080, protocol="tcp")
    both = check_connectivity(list(acme_controls.values()), step)
    assert both.allowed is True
    assert both.reason.startswith(
        "FW-EDGE rule 1 allows dmz -> server port 8080; FW-INT rule 4 allows dmz -> server port 8080"
    )

    other_port = make_step(acme_assets, "T1046", steps.WEB_TO_APP, port=5432, protocol="tcp")
    result = check_connectivity(list(acme_controls.values()), other_port)
    assert result.allowed is False
    assert result.deciding_control_id == acme_controls["FW-EDGE"].id

    internal = acme_controls["FW-INT"]
    strict_config = internal.config.model_copy(update={"rules": internal.config.rules[:4]})
    strict = internal.model_copy(update={"config": strict_config})
    denied = check_connectivity([acme_controls["FW-EDGE"], strict], step)
    assert denied.allowed is False
    assert denied.deciding_control_id == internal.id
    assert "FW-INT has no rule for dmz -> server port 8080" in denied.reason


def test_outbound_web_traffic_is_allowed_at_the_edge(acme_assets: Assets, acme_controls: Controls) -> None:
    controls = list(acme_controls.values())
    out = check_connectivity(controls, make_step(acme_assets, "T1048", ["ADMIN-01", "SW-CORE", "FW-INT", "FW-EDGE", "INTERNET"], port=443))
    assert out.allowed is True
    assert "FW-EDGE rule 2 allows management -> internet port 443" in out.reason
    other = check_connectivity(controls, make_step(acme_assets, "T1048", ["ADMIN-01", "SW-CORE", "FW-INT", "FW-EDGE", "INTERNET"], port=22))
    assert other.allowed is False


def test_skip_types_bypass_connectivity_controls(acme_assets: Assets, acme_controls: Controls) -> None:
    from app.models.enums import ControlType

    controls = list(acme_controls.values())
    phish = make_step(acme_assets, "T1566.001", steps.INTERNET_TO_WS01, port=25)
    assert check_connectivity(controls, phish).allowed is False
    assert check_connectivity(controls, phish, skip_types=[ControlType.FIREWALL]).allowed is True

    bridge = make_step(acme_assets, "T1599", steps.GUEST_TO_WS06)
    assert check_connectivity(controls, bridge).allowed is False
    assert check_connectivity(controls, bridge, skip_types=[ControlType.SEGMENTATION]).allowed is True


def test_internal_firewall_filters_traffic_through_the_core(
    acme_assets: Assets, acme_controls: Controls
) -> None:
    controls = list(acme_controls.values())
    smb = check_connectivity(controls, make_step(acme_assets, "T1021.002", steps.WS01_TO_FS, port=445))
    assert smb.allowed is True
    assert smb.reason == (
        "FW-INT rule 0 allows corporate -> server port 445; "
        "SEG-01 has no rule for VLAN 10 -> VLAN 20, default action allows it"
    )
    assert smb.deciding_control_id == acme_controls["SEG-01"].id

    database = check_connectivity(controls, make_step(acme_assets, "T1005", steps.WS01_TO_DB, port=5432))
    assert database.allowed is False

    admin = check_connectivity(controls, make_step(acme_assets, "T1078", steps.ADMIN_TO_DB, port=5432))
    assert admin.allowed is True
    assert "FW-INT rule 2 allows management -> server port 5432" in admin.reason

    guest = check_connectivity(controls, make_step(acme_assets, "T1190", steps.GUEST_TO_DB, port=5432))
    assert guest.allowed is False
    assert guest.deciding_control_id == acme_controls["FW-INT"].id

    cross_floor = check_connectivity(controls, make_step(acme_assets, "T1021.002", steps.WS01_TO_WS06, port=445))
    assert cross_floor.allowed is False


def test_no_firewall_on_the_path_is_allowed(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1021.002", steps.WS06_TO_WS07, port=445)
    result = check_connectivity(list(acme_controls.values()), step)
    assert result.allowed is True
    assert result.deciding_control_id is None
    assert result.reason == "no firewall or segmentation rule on the path"


def test_firewalls_do_not_see_layer_2_steps(acme_assets: Assets, acme_controls: Controls) -> None:
    step = make_step(acme_assets, "T1557.002", steps.WS01_TO_WS06)
    result = check_connectivity(list(acme_controls.values()), step)
    assert result.allowed is True
    assert result.deciding_control_id is None


def test_segmentation_denies_guest_vlan_to_corporate_vlan(
    acme_assets: Assets, acme_controls: Controls
) -> None:
    controls = list(acme_controls.values())
    step = make_step(acme_assets, "T1021.002", steps.GUEST_TO_WS06, port=445)
    result = check_connectivity(controls, step)
    assert result.allowed is False
    assert result.deciding_control_id == acme_controls["SEG-01"].id
    assert result.rule_index == 0
    assert result.reason == "SEG-01 rule 0 denies VLAN 50 -> VLAN 10"

    arp = check_connectivity(controls, make_step(acme_assets, "T1557.002", steps.GUEST_TO_WS06))
    assert arp.allowed is False
    assert arp.deciding_control_id == acme_controls["SEG-01"].id


def test_segmentation_default_action_and_same_vlan(acme_assets: Assets) -> None:
    deny_all = make_control("SEG", "segmentation", "network_wide", {"vlan_rules": [], "default_action": "deny"})
    crossing = make_step(acme_assets, "T1021.002", steps.WS01_TO_FS, port=445)
    result = check_connectivity([deny_all], crossing)
    assert result.allowed is False
    assert result.rule_index is None
    assert "default action denies" in result.reason

    same_vlan = make_step(acme_assets, "T1021.002", steps.WS06_TO_WS07, port=445)
    assert check_connectivity([deny_all], same_vlan).allowed is True

    no_vlan = make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443)
    assert check_connectivity([deny_all], no_vlan).allowed is True


def test_inline_segmentation_only_applies_on_its_path(acme_assets: Assets) -> None:
    inline = make_control(
        "SEG", "segmentation", "inline", {"vlan_rules": [], "default_action": "deny"},
        assets=[acme_assets["SW-ACCESS-2"]],
    )
    off_path = make_step(acme_assets, "T1021.002", steps.WS01_TO_FS, port=445)
    assert check_connectivity([inline], off_path).allowed is True


def test_first_matching_rule_wins(acme_assets: Assets) -> None:
    step = make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=443, protocol="tcp")
    edge = [acme_assets["FW-EDGE"]]
    deny_first = make_control(
        "FW", "firewall", "inline",
        {"rules": [rule("internet", "dmz", "deny"), rule("internet", "dmz", "allow")], "default_action": "allow", "logging": False},
        assets=edge,
    )
    result = check_connectivity([deny_first], step)
    assert (result.allowed, result.rule_index) == (False, 0)

    allow_first = make_control(
        "FW", "firewall", "inline",
        {"rules": [rule("any", "any", "allow"), rule("internet", "dmz", "deny")], "default_action": "deny", "logging": False},
        assets=edge,
    )
    result = check_connectivity([allow_first], step)
    assert (result.allowed, result.rule_index) == (True, 0)


def test_rules_match_on_protocol_and_port(acme_assets: Assets) -> None:
    firewall = make_control(
        "FW", "firewall", "inline",
        {"rules": [rule("internet", "dmz", "allow", ports=(443,), protocol="tcp")], "default_action": "deny", "logging": False},
        assets=[acme_assets["FW-EDGE"]],
    )

    def allowed(port: int | None, protocol: str) -> bool:
        step = make_step(acme_assets, "T1190", steps.INTERNET_TO_WEB, port=port, protocol=protocol)
        return check_connectivity([firewall], step).allowed

    assert allowed(443, "tcp") is True
    assert allowed(443, "any") is True
    assert allowed(443, "udp") is False
    assert allowed(80, "tcp") is False
    assert allowed(None, "tcp") is False


def test_default_allow_and_disabled_firewall(acme_assets: Assets) -> None:
    step = make_step(acme_assets, "T1190", steps.INTERNET_TO_DB, port=5432)
    edge = [acme_assets["FW-EDGE"]]
    open_firewall = make_control(
        "FW", "firewall", "inline", {"rules": [], "default_action": "allow", "logging": False}, assets=edge
    )
    result = check_connectivity([open_firewall], step)
    assert (result.allowed, result.rule_index) == (True, None)
    assert "default action allows" in result.reason

    closed_but_disabled = make_control(
        "FW", "firewall", "inline", {"rules": [], "default_action": "deny", "logging": False},
        assets=edge, enabled=False,
    )
    assert check_connectivity([closed_but_disabled], step).allowed is True
    assert check_connectivity([], step).allowed is True
