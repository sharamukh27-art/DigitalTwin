"""Text and defaults used by the remediation rules: titles, vendor-neutral snippets, default configs."""

from typing import Any

from app.models.enums import ControlType, EffortHint, PlacementKind

CONNECTIVITY_CAVEAT = (
    "The twin models attack paths, not business traffic. Confirm that no legitimate flow "
    "needs this before applying."
)
NEW_CONTROL_CAVEAT = "This adds a control that does not exist yet. The default config is a starting point."

DEFAULT_VALUES: dict[tuple[ControlType, str], Any] = {
    (ControlType.IDENTITY_POLICY, "lockout_threshold"): 5,
}

# (control type, config key) -> (title with {value} and {code}, snippet lines, effort)
REQUIREMENT_TEXT: dict[tuple[ControlType, str], tuple[str, str, EffortHint]] = {
    (ControlType.SWITCH_SECURITY, "dynamic_arp_inspection"): (
        "Enable dynamic ARP inspection on {code}",
        "ip arp inspection vlan {vlans}",
        EffortHint.LOW,
    ),
    (ControlType.SWITCH_SECURITY, "dhcp_snooping"): (
        "Enable DHCP snooping on {code}",
        "ip dhcp snooping\nip dhcp snooping vlan {vlans}",
        EffortHint.LOW,
    ),
    (ControlType.SWITCH_SECURITY, "port_security"): (
        "Enable port security on {code}",
        "switchport port-security\nswitchport port-security maximum 2",
        EffortHint.LOW,
    ),
    (ControlType.NAC_8021X, "enforced"): (
        "Enforce 802.1X on {code}",
        "dot1x system-auth-control\nauthentication port-control auto",
        EffortHint.MEDIUM,
    ),
    (ControlType.NAC_8021X, "mac_auth_bypass_allowed"): (
        "Disable MAC authentication bypass on {code}",
        "no mab\n# require 802.1X on every access port; record each exception with an owner",
        EffortHint.MEDIUM,
    ),
    (ControlType.IDENTITY_POLICY, "lockout_threshold"): (
        "Set an account lockout threshold on {code}",
        "account lockout threshold: {value} failed attempts\nlockout duration: 15 minutes",
        EffortHint.LOW,
    ),
    (ControlType.SIEM, "ueba"): (
        "Enable user behaviour analytics on {code}",
        "enable the UEBA / anomaly detection module\nbaseline sign-in behaviour per account",
        EffortHint.MEDIUM,
    ),
    (ControlType.SIEM, "log_sources"): (
        "Send {value} logs to {code}",
        "forward {value} logs to the SIEM collector",
        EffortHint.LOW,
    ),
    (ControlType.IDS_IPS, "signature_sets"): (
        "Load {value} signatures on {code}",
        "enable signature set: {value}",
        EffortHint.LOW,
    ),
    (ControlType.MFA, "enforced_for"): (
        "Require multi-factor authentication for {value} on {code}",
        "require multi-factor authentication for service: {value}",
        EffortHint.MEDIUM,
    ),
    (ControlType.FIREWALL, "logging"): (
        "Enable logging on {code}",
        "log allowed and denied sessions\nforward the logs to the SIEM",
        EffortHint.LOW,
    ),
    (ControlType.HONEYPOT, "alerting"): (
        "Forward alerts from {code} to the SOC",
        "send decoy interaction alerts to the SIEM\nalert on any connection to a decoy",
        EffortHint.LOW,
    ),
    (ControlType.HONEYPOT, "decoy_services"): (
        "Add a {value} decoy to {code}",
        "deploy a decoy service: {value}",
        EffortHint.LOW,
    ),
    (ControlType.EMAIL_GATEWAY, "attachment_sandboxing"): (
        "Enable attachment sandboxing on {code}",
        "detonate attachments in a sandbox before delivery",
        EffortHint.MEDIUM,
    ),
}
GENERIC_REQUIREMENT = ("Set {key} to {value} on {code}", "set {key} = {value}", EffortHint.MEDIUM)

# control type -> (new mode, snippet)
BLOCKING_MODE: dict[ControlType, tuple[str, str]] = {
    ControlType.WAF: ("block", "set WAF mode: prevention (block)\n# review the detect-mode logs for false positives first"),
    ControlType.IDS_IPS: ("ips", "set sensor mode: inline prevention (IPS)\n# place the sensor inline or enable active response"),
    ControlType.EDR: ("block", "set EDR policy: block"),
    ControlType.DLP: ("block", "set DLP policy: block"),
}

# placement kind -> (title, snippet), with {code}, {type} and {value}
PLACEMENT_TEXT: dict[PlacementKind, tuple[str, str]] = {
    PlacementKind.HOST: (
        "Deploy {code} to {value}",
        "install the {type} agent on {value}\nassign it to the {code} policy",
    ),
    PlacementKind.SENSOR: (
        "Extend {code} to the {value} zone",
        "add a {type} sensor (SPAN port or tap) for zone: {value}",
    ),
    PlacementKind.IDENTITY: (
        "Protect the {value} service with {code}",
        "require {type} for service: {value}",
    ),
    PlacementKind.INLINE: (
        "Put {value} behind {code}",
        "route traffic for {value} through {code}",
    ),
}

BACKUP_SNIPPET = (
    "configure an offline or immutable backup copy for: {assets}\n"
    "test a restore from that copy every quarter"
)
FIREWALL_DENY_SNIPPET = (
    "deny {protocol} from zone {src} to zone {dst} port {port}\n# place before {position} on {code}"
)

# Defaults for a control created by the new-control rule: (placement kind, config)
NEW_CONTROL_DEFAULTS: dict[ControlType, tuple[PlacementKind, dict[str, Any]]] = {
    ControlType.DLP: (PlacementKind.NETWORK_WIDE, {"mode": "block", "monitored_channels": ["web", "email"]}),
    ControlType.EDR: (PlacementKind.HOST, {"mode": "block"}),
    ControlType.WAF: (PlacementKind.INLINE, {"mode": "block", "rulesets": ["owasp-crs"]}),
    ControlType.IDS_IPS: (
        PlacementKind.SENSOR,
        {"mode": "ips", "signature_sets": ["network", "web", "arp", "smb", "auth"]},
    ),
    ControlType.MFA: (PlacementKind.IDENTITY, {"enforced_for": []}),
    ControlType.IDENTITY_POLICY: (PlacementKind.IDENTITY, {"lockout_threshold": 5, "password_min_length": 14}),
    ControlType.EMAIL_GATEWAY: (PlacementKind.IDENTITY, {"attachment_sandboxing": True, "url_rewriting": True}),
    ControlType.NAC_8021X: (PlacementKind.INLINE, {"enforced": True, "mac_auth_bypass_allowed": False}),
    ControlType.SWITCH_SECURITY: (
        PlacementKind.INLINE,
        {"port_security": True, "max_macs_per_port": 2, "dhcp_snooping": True, "dynamic_arp_inspection": True},
    ),
}
NEW_CONTROL_CODES: dict[ControlType, str] = {
    ControlType.DLP: "DLP",
    ControlType.EDR: "EDR",
    ControlType.WAF: "WAF",
    ControlType.IDS_IPS: "IPS",
    ControlType.MFA: "MFA",
    ControlType.IDENTITY_POLICY: "IDP",
    ControlType.EMAIL_GATEWAY: "MAIL",
    ControlType.NAC_8021X: "NAC",
    ControlType.SWITCH_SECURITY: "SWSEC",
}
NEW_CONTROL_NAMES: dict[ControlType, str] = {
    ControlType.DLP: "Data loss prevention",
    ControlType.EDR: "Endpoint detection and response",
    ControlType.WAF: "Web application firewall",
    ControlType.IDS_IPS: "Network intrusion prevention",
    ControlType.MFA: "Multi-factor authentication",
    ControlType.IDENTITY_POLICY: "Identity and password policy",
    ControlType.EMAIL_GATEWAY: "Secure email gateway",
    ControlType.NAC_8021X: "802.1X network access control",
    ControlType.SWITCH_SECURITY: "Switch security",
}
