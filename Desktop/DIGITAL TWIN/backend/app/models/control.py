"""Security control models: placement, one config schema per control type, CRUD models."""

from collections.abc import Sequence
from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.models.asset import Vlan
from app.models.common import Code, Name, PortNumber, StoredModel, reject_nulls
from app.models.enums import (
    ControlType,
    EnforcementMode,
    IdsMode,
    PlacementKind,
    Protocol,
    RuleAction,
    SignatureSet,
    Zone,
)

ZoneOrAny = Union[Zone, Literal["any"]]


class ConfigModel(BaseModel):
    """Base of every control config. Unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")


class FirewallRule(ConfigModel):
    """One firewall rule. Rules are checked in order and the first match wins."""

    src_zone: ZoneOrAny
    dst_zone: ZoneOrAny
    ports: list[PortNumber] = Field(default_factory=list, description="Empty means all ports.")
    protocol: Protocol = Protocol.ANY
    action: RuleAction


class FirewallConfig(ConfigModel):
    """Zone-based packet filter."""

    rules: list[FirewallRule] = Field(default_factory=list)
    default_action: RuleAction
    logging: bool


class VlanRule(ConfigModel):
    """One VLAN-to-VLAN rule."""

    src_vlan: Vlan
    dst_vlan: Vlan
    action: RuleAction


class SegmentationConfig(ConfigModel):
    """VLAN segmentation policy."""

    vlan_rules: list[VlanRule] = Field(default_factory=list)
    default_action: RuleAction


class WafConfig(ConfigModel):
    """Web application firewall."""

    mode: EnforcementMode
    rulesets: list[str] = Field(default_factory=list)


class IdsIpsConfig(ConfigModel):
    """Network intrusion detection or prevention."""

    mode: IdsMode
    signature_sets: list[SignatureSet]


class Nac8021xConfig(ConfigModel):
    """802.1X network access control."""

    enforced: bool
    mac_auth_bypass_allowed: bool


class SwitchSecurityConfig(ConfigModel):
    """Layer 2 switch hardening features."""

    port_security: bool
    max_macs_per_port: int = Field(ge=1)
    dhcp_snooping: bool
    dynamic_arp_inspection: bool


class MfaConfig(ConfigModel):
    """Multi-factor authentication."""

    enforced_for: list[str]


class IdentityPolicyConfig(ConfigModel):
    """Account lockout and password policy."""

    lockout_threshold: int | None = Field(ge=1)
    password_min_length: int = Field(ge=1)


class EdrConfig(ConfigModel):
    """Endpoint detection and response."""

    mode: EnforcementMode


class EmailGatewayConfig(ConfigModel):
    """Secure email gateway."""

    attachment_sandboxing: bool
    url_rewriting: bool


class DlpConfig(ConfigModel):
    """Data loss prevention."""

    mode: EnforcementMode
    monitored_channels: list[str] = Field(default_factory=list)


class SiemConfig(ConfigModel):
    """Log collection and correlation."""

    log_sources: list[str]
    ueba: bool


class BackupConfig(ConfigModel):
    """Backups. No detection capability; reduces impact in a later phase."""

    offline_copies: bool
    tested_restore: bool


class HoneypotConfig(ConfigModel):
    """Decoy services placed in a zone. Detects whoever touches them; never blocks."""

    decoy_services: list[str]
    alerting: bool


ControlConfig = Union[
    FirewallConfig,
    SegmentationConfig,
    WafConfig,
    IdsIpsConfig,
    Nac8021xConfig,
    SwitchSecurityConfig,
    MfaConfig,
    IdentityPolicyConfig,
    EdrConfig,
    EmailGatewayConfig,
    DlpConfig,
    SiemConfig,
    BackupConfig,
    HoneypotConfig,
]

CONFIG_MODELS: dict[ControlType, type[ConfigModel]] = {
    ControlType.FIREWALL: FirewallConfig,
    ControlType.SEGMENTATION: SegmentationConfig,
    ControlType.WAF: WafConfig,
    ControlType.IDS_IPS: IdsIpsConfig,
    ControlType.NAC_8021X: Nac8021xConfig,
    ControlType.SWITCH_SECURITY: SwitchSecurityConfig,
    ControlType.MFA: MfaConfig,
    ControlType.IDENTITY_POLICY: IdentityPolicyConfig,
    ControlType.EDR: EdrConfig,
    ControlType.EMAIL_GATEWAY: EmailGatewayConfig,
    ControlType.DLP: DlpConfig,
    ControlType.SIEM: SiemConfig,
    ControlType.BACKUP: BackupConfig,
    ControlType.HONEYPOT: HoneypotConfig,
}


def placement_errors(
    kind: PlacementKind, assets: Sequence[str], zones: Sequence[Zone], services: Sequence[str]
) -> list[str]:
    """Return what a placement of this kind is missing. Empty when it is usable."""
    if kind in (PlacementKind.INLINE, PlacementKind.HOST) and not assets:
        return [f"{kind.value} placement needs at least one asset"]
    if kind == PlacementKind.SENSOR and not zones:
        return ["sensor placement needs at least one zone"]
    if kind == PlacementKind.IDENTITY and not services:
        return ["identity placement needs at least one service"]
    return []


class Placement(BaseModel):
    """Where a control sits. Which lists matter depends on `kind`.

    inline: on the path through `asset_ids`, or in front of them.
    sensor: watches traffic in `zones`.
    host: runs on `asset_ids`.
    identity: protects logins to `services`.
    network_wide: sees everything that produces logs.
    """

    kind: PlacementKind
    asset_ids: list[str] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


def _format_config_errors(exc: ValidationError) -> str:
    """Flatten config validation errors into one message."""
    parts = []
    for error in exc.errors():
        location = ".".join(["config", *(str(part) for part in error["loc"])])
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


class ControlAttributes(BaseModel):
    """Control fields shared by the API and the import file, without placement."""

    code: Code
    name: Name
    type: ControlType
    enabled: bool = True
    config: ControlConfig

    @model_validator(mode="before")
    @classmethod
    def _config_matches_type(cls, data: Any) -> Any:
        """Validate `config` against the schema selected by `type`."""
        if not isinstance(data, dict) or data.get("config") is None:
            return data
        try:
            control_type = ControlType(data.get("type"))
        except ValueError as exc:
            allowed = ", ".join(item.value for item in ControlType)
            raise ValueError(f"type must be one of: {allowed}") from exc
        expected = CONFIG_MODELS[control_type]
        config = data["config"]
        if isinstance(config, ConfigModel):
            if not isinstance(config, expected):
                raise ValueError(f"config must be a {control_type.value} config")
            return data
        try:
            parsed = expected.model_validate(config)
        except ValidationError as exc:
            raise ValueError(_format_config_errors(exc)) from exc
        return {**data, "config": parsed}


class ControlBase(ControlAttributes):
    """Fields a client supplies for a control."""

    placement: Placement


class ControlCreate(ControlBase):
    """Request body for creating a control."""


class ControlUpdate(BaseModel):
    """Request body for updating a control. Only sent fields change.

    `config` is merged key by key into the current config. `type` cannot change.
    """

    code: Code | None = None
    name: Name | None = None
    enabled: bool | None = None
    placement: Placement | None = None
    config: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _no_nulls(self) -> "ControlUpdate":
        reject_nulls(self, frozenset())
        return self


class SecurityControl(ControlBase, StoredModel):
    """A stored security control."""

    network_id: str


class ControlRead(SecurityControl):
    """Response model for a control."""
