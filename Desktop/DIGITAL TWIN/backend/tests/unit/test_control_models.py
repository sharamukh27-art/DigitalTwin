"""Config validation for every control type."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.models.control import (
    CONFIG_MODELS,
    ControlCreate,
    EdrConfig,
    WafConfig,
    placement_errors,
)
from app.models.enums import ControlType, PlacementKind, Zone

GOOD_CONFIGS: dict[str, dict[str, Any]] = {
    "firewall": {
        "rules": [
            {"src_zone": "internet", "dst_zone": "dmz", "ports": [80, 443], "protocol": "tcp", "action": "allow"},
            {"src_zone": "management", "dst_zone": "any", "action": "allow"},
        ],
        "default_action": "deny",
        "logging": True,
    },
    "segmentation": {
        "vlan_rules": [{"src_vlan": 50, "dst_vlan": 10, "action": "deny"}],
        "default_action": "allow",
    },
    "waf": {"mode": "block", "rulesets": ["owasp-crs"]},
    "ids_ips": {"mode": "ips", "signature_sets": ["network", "web", "arp", "smb", "auth"]},
    "nac_8021x": {"enforced": True, "mac_auth_bypass_allowed": False},
    "switch_security": {
        "port_security": True,
        "max_macs_per_port": 2,
        "dhcp_snooping": True,
        "dynamic_arp_inspection": True,
    },
    "mfa": {"enforced_for": ["vpn", "email"]},
    "identity_policy": {"lockout_threshold": 5, "password_min_length": 12},
    "edr": {"mode": "block"},
    "email_gateway": {"attachment_sandboxing": True, "url_rewriting": False},
    "dlp": {"mode": "detect", "monitored_channels": ["email", "web"]},
    "siem": {"log_sources": ["auth", "windows"], "ueba": True},
    "backup": {"offline_copies": True, "tested_restore": True},
    "honeypot": {"decoy_services": ["smb", "ssh"], "alerting": True},
}

BAD_CONFIGS: dict[str, dict[str, Any]] = {
    "firewall": {"rules": [{"src_zone": "moon", "dst_zone": "dmz", "action": "allow"}], "default_action": "deny", "logging": True},
    "segmentation": {"vlan_rules": [{"src_vlan": 5000, "dst_vlan": 10, "action": "deny"}], "default_action": "allow"},
    "waf": {"mode": "observe"},
    "ids_ips": {"mode": "ids", "signature_sets": ["quantum"]},
    "nac_8021x": {"enforced": True},
    "switch_security": {"port_security": True, "max_macs_per_port": 0, "dhcp_snooping": True, "dynamic_arp_inspection": True},
    "mfa": {"enforced_for": "vpn"},
    "identity_policy": {"lockout_threshold": 0, "password_min_length": 12},
    "edr": {"mode": "block", "unknown_key": 1},
    "email_gateway": {"attachment_sandboxing": "maybe", "url_rewriting": False},
    "dlp": {"monitored_channels": ["email"]},
    "siem": {"log_sources": ["auth"]},
    "backup": {"offline_copies": True},
    "honeypot": {"decoy_services": "smb", "alerting": True},
}


def body(control_type: str, config: Any) -> dict[str, Any]:
    return {
        "code": "C-1",
        "name": "Control",
        "type": control_type,
        "placement": {"kind": "network_wide"},
        "config": config,
    }


def test_test_data_covers_all_14_types() -> None:
    all_types = {item.value for item in ControlType}
    assert len(all_types) == 14
    assert set(GOOD_CONFIGS) == set(BAD_CONFIGS) == set(CONFIG_MODELS) == all_types


@pytest.mark.parametrize("control_type", sorted(GOOD_CONFIGS))
def test_good_config_is_accepted(control_type: str) -> None:
    control = ControlCreate.model_validate(body(control_type, GOOD_CONFIGS[control_type]))
    assert isinstance(control.config, CONFIG_MODELS[ControlType(control_type)])
    assert control.enabled is True


@pytest.mark.parametrize("control_type", sorted(BAD_CONFIGS))
def test_bad_config_is_rejected(control_type: str) -> None:
    with pytest.raises(ValidationError, match="config"):
        ControlCreate.model_validate(body(control_type, BAD_CONFIGS[control_type]))


def test_config_of_another_type_is_rejected() -> None:
    with pytest.raises(ValidationError, match="config"):
        ControlCreate.model_validate(body("edr", GOOD_CONFIGS["firewall"]))
    with pytest.raises(ValidationError, match="config must be a edr config"):
        ControlCreate.model_validate(body("edr", WafConfig(mode="block")))
    assert ControlCreate.model_validate(body("edr", EdrConfig(mode="block"))).config.mode.value == "block"


def test_unknown_type_and_missing_config_are_rejected() -> None:
    with pytest.raises(ValidationError, match="type must be one of"):
        ControlCreate.model_validate(body("antivirus", {"mode": "block"}))
    with pytest.raises(ValidationError):
        ControlCreate.model_validate(body("edr", None))


def test_identity_policy_lockout_may_be_null_but_must_be_present() -> None:
    control = ControlCreate.model_validate(
        body("identity_policy", {"lockout_threshold": None, "password_min_length": 8})
    )
    assert control.config.lockout_threshold is None
    with pytest.raises(ValidationError, match="lockout_threshold"):
        ControlCreate.model_validate(body("identity_policy", {"password_min_length": 8}))


def test_placement_errors() -> None:
    assert placement_errors(PlacementKind.INLINE, [], [], []) == [
        "inline placement needs at least one asset"
    ]
    assert placement_errors(PlacementKind.HOST, ["a"], [], []) == []
    assert placement_errors(PlacementKind.SENSOR, ["a"], [], []) != []
    assert placement_errors(PlacementKind.SENSOR, [], [Zone.DMZ], []) == []
    assert placement_errors(PlacementKind.IDENTITY, [], [], []) != []
    assert placement_errors(PlacementKind.IDENTITY, [], [], ["vpn"]) == []
    assert placement_errors(PlacementKind.NETWORK_WIDE, [], [], []) == []
