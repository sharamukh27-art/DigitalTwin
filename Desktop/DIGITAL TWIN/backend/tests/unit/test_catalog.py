"""Capability catalog content and requirement checks."""

from app.controls import catalog
from app.controls.catalog import Capability
from app.models.control import (
    EdrConfig,
    IdentityPolicyConfig,
    IdsIpsConfig,
    Nac8021xConfig,
    WafConfig,
)
from app.models.enums import CapabilityAction, ControlType
from app.twin import techniques

EXPECTED: dict[str, dict[str, tuple[str, float]]] = {
    "waf": {"T1190": ("block", 0.80), "T1505.003": ("detect", 0.50)},
    "ids_ips": {
        "T1557.002": ("detect", 0.70),
        "T1046": ("detect", 0.80),
        "T1190": ("block", 0.60),
        "T1021.002": ("detect", 0.55),
        "T1110": ("detect", 0.60),
        "T1048": ("detect", 0.60),
    },
    "nac_8021x": {"T1599": ("block", 0.90), "T1557.002": ("detect", 0.40)},
    "switch_security": {"T1557.002": ("block", 0.90), "T1599": ("detect", 0.60)},
    "mfa": {"T1078": ("block", 0.90), "T1110": ("block", 0.95), "T1133": ("block", 0.90)},
    "identity_policy": {"T1110": ("block", 0.70)},
    "edr": {
        "T1003": ("block", 0.85),
        "T1486": ("block", 0.80),
        "T1505.003": ("detect", 0.70),
        "T1021.002": ("detect", 0.60),
        "T1566.001": ("detect", 0.60),
        "T1005": ("detect", 0.30),
    },
    "email_gateway": {"T1566.001": ("block", 0.70)},
    "dlp": {"T1048": ("block", 0.70), "T1005": ("detect", 0.50)},
    "siem": {"T1110": ("detect", 0.80), "T1078": ("detect", 0.50), "T1021.002": ("detect", 0.40)},
    "firewall": {"T1046": ("log", 0.50)},
    "segmentation": {},
    "backup": {},
    "honeypot": {"T1046": ("detect", 0.85), "T1021.002": ("detect", 0.45), "T1110": ("detect", 0.40)},
}


def test_catalog_matches_specification() -> None:
    for control_type in ControlType:
        actual = {
            technique_id: (capability.action.value, capability.confidence)
            for technique_id, capability in catalog.capabilities_for(control_type).items()
        }
        assert actual == EXPECTED[control_type.value], control_type


def test_every_technique_id_exists_in_the_technique_catalog() -> None:
    known = {technique.id for technique in techniques.all()}
    for control_type in ControlType:
        assert set(catalog.capabilities_for(control_type)) <= known


def test_layer_3_controls_have_no_capability_for_arp_or_bridging() -> None:
    for control_type in (ControlType.FIREWALL, ControlType.SEGMENTATION, ControlType.WAF):
        assert catalog.get_capability(control_type, "T1557.002") is None
        assert catalog.get_capability(control_type, "T1599") is None
        assert catalog.min_layer(control_type) >= 3


def test_min_layers() -> None:
    assert catalog.min_layer(ControlType.SWITCH_SECURITY) == 2
    assert catalog.min_layer(ControlType.FIREWALL) == 3
    assert catalog.min_layer(ControlType.DLP) == 4
    assert catalog.min_layer(ControlType.WAF) == 7
    assert catalog.min_layer(ControlType.HONEYPOT) == 4


def test_requirements_equals_contains_and_not_null() -> None:
    nac = catalog.get_capability(ControlType.NAC_8021X, "T1599")
    assert nac is not None
    assert catalog.failed_requirements(nac, Nac8021xConfig(enforced=True, mac_auth_bypass_allowed=False)) == []
    assert catalog.failed_requirements(nac, Nac8021xConfig(enforced=False, mac_auth_bypass_allowed=True)) == [
        "enforced is false",
        "mac_auth_bypass_allowed is true",
    ]

    ids = catalog.get_capability(ControlType.IDS_IPS, "T1557.002")
    assert ids is not None
    assert catalog.failed_requirements(ids, IdsIpsConfig(mode="ids", signature_sets=["arp"])) == []
    assert catalog.failed_requirements(ids, IdsIpsConfig(mode="ids", signature_sets=["web"])) == [
        "signature_sets does not contain arp"
    ]

    lockout = catalog.get_capability(ControlType.IDENTITY_POLICY, "T1110")
    assert lockout is not None
    assert catalog.failed_requirements(
        lockout, IdentityPolicyConfig(lockout_threshold=None, password_min_length=8)
    ) == ["lockout_threshold is not set"]
    assert catalog.failed_requirements(
        lockout, IdentityPolicyConfig(lockout_threshold=5, password_min_length=8)
    ) == []


def test_block_is_downgraded_in_detect_modes() -> None:
    block = Capability(action="block", confidence=0.8)
    detect = Capability(action="detect", confidence=0.5)
    assert catalog.effective_action(block, WafConfig(mode="detect")) == (
        CapabilityAction.DETECT,
        CapabilityAction.BLOCK,
    )
    assert catalog.effective_action(block, WafConfig(mode="block")) == (CapabilityAction.BLOCK, None)
    assert catalog.effective_action(block, EdrConfig(mode="detect"))[0] == CapabilityAction.DETECT
    assert catalog.effective_action(block, IdsIpsConfig(mode="ids", signature_sets=[]))[0] == CapabilityAction.DETECT
    assert catalog.effective_action(block, IdsIpsConfig(mode="ips", signature_sets=[]))[0] == CapabilityAction.BLOCK
    assert catalog.effective_action(detect, WafConfig(mode="detect")) == (CapabilityAction.DETECT, None)
