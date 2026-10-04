"""String enums shared by every phase. Defined once, reused everywhere."""

from enum import Enum, IntEnum


class AssetType(str, Enum):
    """Kind of device or service represented by an asset."""

    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    SERVER = "server"
    DATABASE = "database"
    DOMAIN_CONTROLLER = "domain_controller"
    FILE_SERVER = "file_server"
    WEB_SERVER = "web_server"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    VPN_GATEWAY = "vpn_gateway"
    IOT = "iot"
    CLOUD_SERVICE = "cloud_service"
    ATTACKER_NODE = "attacker_node"


class Zone(str, Enum):
    """Network security zone an asset belongs to."""

    INTERNET = "internet"
    DMZ = "dmz"
    CORPORATE = "corporate"
    SERVER = "server"
    MANAGEMENT = "management"
    GUEST = "guest"


ZONE_TRUST: dict[Zone, int] = {
    Zone.INTERNET: 0,
    Zone.GUEST: 10,
    Zone.DMZ: 30,
    Zone.CORPORATE: 60,
    Zone.SERVER: 70,
    Zone.MANAGEMENT: 90,
}

ZONES_BY_TRUST: tuple[Zone, ...] = tuple(sorted(ZONE_TRUST, key=lambda zone: ZONE_TRUST[zone]))


class LinkType(str, Enum):
    """Physical or logical medium of a link between two assets."""

    ETHERNET = "ethernet"
    WIFI = "wifi"
    VPN = "vpn"
    WAN = "wan"
    TRUNK = "trunk"
    VIRTUAL = "virtual"


class Criticality(IntEnum):
    """Business criticality of an asset, 1 (lowest) to 5 (highest)."""

    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class Protocol(str, Enum):
    """Transport protocol carried by a port or allowed on a link."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class DataClassification(str, Enum):
    """Sensitivity of the data an asset stores or processes."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Tactic(str, Enum):
    """MITRE ATT&CK enterprise tactics."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ControlType(str, Enum):
    """Kind of security control."""

    FIREWALL = "firewall"
    SEGMENTATION = "segmentation"
    WAF = "waf"
    IDS_IPS = "ids_ips"
    NAC_8021X = "nac_8021x"
    SWITCH_SECURITY = "switch_security"
    MFA = "mfa"
    IDENTITY_POLICY = "identity_policy"
    EDR = "edr"
    EMAIL_GATEWAY = "email_gateway"
    DLP = "dlp"
    SIEM = "siem"
    BACKUP = "backup"
    HONEYPOT = "honeypot"


class PlacementKind(str, Enum):
    """How a control is positioned relative to the traffic or hosts it protects."""

    INLINE = "inline"
    SENSOR = "sensor"
    HOST = "host"
    IDENTITY = "identity"
    NETWORK_WIDE = "network_wide"


class RuleAction(str, Enum):
    """Decision of a firewall or segmentation rule."""

    ALLOW = "allow"
    DENY = "deny"


class EnforcementMode(str, Enum):
    """Whether a control only alerts or also stops the activity."""

    DETECT = "detect"
    BLOCK = "block"


class IdsMode(str, Enum):
    """Passive (ids) or inline blocking (ips) operation."""

    IDS = "ids"
    IPS = "ips"


class SignatureSet(str, Enum):
    """Signature families an IDS/IPS can load."""

    NETWORK = "network"
    WEB = "web"
    ARP = "arp"
    SMB = "smb"
    AUTH = "auth"


class CapabilityAction(str, Enum):
    """What a control can do about a technique, per the capability catalog."""

    DETECT = "detect"
    BLOCK = "block"
    LOG = "log"


class ControlOutcome(str, Enum):
    """Result of evaluating one control against one step."""

    BLOCKED = "blocked"
    DETECTED = "detected"
    LOGGED = "logged"
    MISSED = "missed"
    NOT_APPLICABLE = "not_applicable"


class CoverageStatus(str, Enum):
    """State of one control/technique cell in the coverage matrix."""

    ACTIVE = "active"
    MISSED_REQUIREMENT = "missed_requirement"
    NONE = "none"


class AttackerProfile(str, Enum):
    """Who the simulated attacker is at the start of a scenario."""

    OUTSIDER = "outsider"
    INSIDER = "insider"
    COMPROMISED_DEVICE = "compromised_device"


class GoalKind(str, Enum):
    """What a scenario is trying to achieve."""

    REACH_ASSET = "reach_asset"
    REACH_ANY_CRITICAL = "reach_any_critical"
    EXFILTRATE = "exfiltrate"
    ENCRYPT = "encrypt"


class EffectKind(str, Enum):
    """What an attacker gains when a step succeeds. `move_to` takes an argument: move_to:<code-or-role>."""

    GAIN_FOOTHOLD = "gain_foothold"
    OBTAIN_CREDENTIALS = "obtain_credentials"
    ESCALATE_PRIVILEGE = "escalate_privilege"
    MOVE_TO = "move_to"
    READ_DATA = "read_data"
    ENCRYPT_DATA = "encrypt_data"
    EXFILTRATE_DATA = "exfiltrate_data"


class SelectorKind(str, Enum):
    """How a step picks its target when it does not name an asset code."""

    NEXT_HOP_TOWARD_GOAL = "next_hop_toward_goal"
    ANY_IN_ZONE = "any_in_zone"
    ROLE = "role"
    CURRENT_POSITION = "current_position"


class RunStatus(str, Enum):
    """Lifecycle state of a simulation run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class StepOutcome(str, Enum):
    """Result of one scenario step."""

    BLOCKED = "blocked"
    DETECTED_NOT_BLOCKED = "detected_not_blocked"
    UNDETECTED = "undetected"


class FinalOutcome(str, Enum):
    """Result of a whole simulation run."""

    CONTAINED = "contained"
    PARTIALLY_CONTAINED = "partially_contained"
    OBJECTIVE_REACHED = "objective_reached"


class RiskBand(str, Enum):
    """Risk level of a score from 0 to 100."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WeakestLinkKind(str, Enum):
    """What kind of failure let an attack go furthest."""

    MISSED_CONTROL = "missed_control"
    BLIND_SPOT = "blind_spot"
    CONNECTIVITY_HOLE = "connectivity_hole"


class PatchTarget(str, Enum):
    """What a what-if patch operation changes."""

    CONTROL = "control"
    ASSET = "asset"


class SourceKind(str, Enum):
    """Kind of knowledge base source a chunk comes from."""

    ATTACK = "attack"
    D3FEND = "d3fend"
    NIST = "nist"
    CIS = "cis"
    POLICY = "policy"


class EffortHint(str, Enum):
    """Rough effort of carrying out a recommendation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RemediationStatus(str, Enum):
    """Lifecycle state of a remediation."""

    PROPOSED = "proposed"
    VERIFIED = "verified"
    REJECTED = "rejected"
    APPROVED = "approved"
    APPLIED = "applied"


class RemediationRule(str, Enum):
    """Which deterministic rule produced a remediation."""

    MISSED_REQUIREMENT = "missed_requirement"
    MODE_DOWNGRADE = "mode_downgrade"
    PLACEMENT_GAP = "placement_gap"
    NEW_CONTROL = "new_control"
    OFFLINE_BACKUP = "offline_backup"
    CONNECTIVITY_HOLE = "connectivity_hole"
