"""Connectivity enforcement: is traffic for a step allowed at all?

This is independent of the technique. Firewalls and segmentation decide here;
technique detection and blocking live in evaluator.py.
"""

from collections.abc import Collection, Sequence

from app.controls import catalog
from app.models.asset import Asset
from app.models.control import FirewallConfig, FirewallRule, SecurityControl, SegmentationConfig
from app.models.enums import ControlType, PlacementKind, Protocol, RuleAction
from app.models.evaluation import ConnectivityResult, StepContext


FLOW = "flow"
"""Placeholder technique id for a connectivity check that is not tied to a technique."""


def _path_position(control: SecurityControl, ctx: StepContext) -> int | None:
    """Return where on the path the control's first asset sits, or None when it is not on it."""
    positions = [
        index
        for index, asset_id in enumerate(ctx.path_asset_ids)
        if asset_id in control.placement.asset_ids
    ]
    return min(positions) if positions else None


def _rule_matches(rule: FirewallRule, ctx: StepContext) -> bool:
    """Return True when a firewall rule applies to the step's zones, protocol and port."""
    if rule.src_zone != "any" and rule.src_zone != ctx.source_asset.zone:
        return False
    if rule.dst_zone != "any" and rule.dst_zone != ctx.target_asset.zone:
        return False
    if Protocol.ANY not in (rule.protocol, ctx.protocol) and rule.protocol != ctx.protocol:
        return False
    if rule.ports and ctx.port not in rule.ports:
        return False
    return True


def _describe(ctx: StepContext) -> str:
    """Summarise the traffic of a step for a reason string."""
    port = f" port {ctx.port}" if ctx.port is not None else ""
    return f"{ctx.source_asset.zone.value} -> {ctx.target_asset.zone.value}{port}"


def _firewall_decision(
    control: SecurityControl, config: FirewallConfig, ctx: StepContext
) -> tuple[RuleAction, int | None, str]:
    """Return (action, rule_index, reason) of one firewall for the step."""
    for index, rule in enumerate(config.rules):
        if _rule_matches(rule, ctx):
            verb = "allows" if rule.action == RuleAction.ALLOW else "denies"
            return rule.action, index, f"{control.code} rule {index} {verb} {_describe(ctx)}"
    verb = "allows" if config.default_action == RuleAction.ALLOW else "denies"
    return (
        config.default_action,
        None,
        f"{control.code} has no rule for {_describe(ctx)}, default action {verb} it",
    )


def _segmentation_decision(
    control: SecurityControl, config: SegmentationConfig, src_vlan: int, dst_vlan: int
) -> tuple[RuleAction, int | None, str]:
    """Return (action, rule_index, reason) of one segmentation control for a VLAN crossing."""
    crossing = f"VLAN {src_vlan} -> VLAN {dst_vlan}"
    for index, rule in enumerate(config.vlan_rules):
        if rule.src_vlan == src_vlan and rule.dst_vlan == dst_vlan:
            verb = "allows" if rule.action == RuleAction.ALLOW else "denies"
            return rule.action, index, f"{control.code} rule {index} {verb} {crossing}"
    verb = "allows" if config.default_action == RuleAction.ALLOW else "denies"
    return (
        config.default_action,
        None,
        f"{control.code} has no rule for {crossing}, default action {verb} it",
    )


def _segmentation_applies(control: SecurityControl, ctx: StepContext) -> bool:
    """Network-wide segmentation always applies; inline segmentation must be on the path."""
    if control.placement.kind == PlacementKind.NETWORK_WIDE:
        return True
    return _path_position(control, ctx) is not None


def check_connectivity(
    controls: Sequence[SecurityControl],
    ctx: StepContext,
    skip_types: Collection[ControlType] = (),
) -> ConnectivityResult:
    """Decide whether the step's traffic can flow from source to target.

    `skip_types` names connectivity control types (firewall, segmentation) this step
    is not subject to, for example a phishing email or a VLAN-hopping technique.

    Enabled inline firewalls on the path are checked in path order. For each one the
    first matching rule wins, otherwise its default action applies. Every firewall
    must allow the traffic. Firewalls are skipped for steps below layer 3, which they
    cannot see. Then segmentation controls are checked when source and target sit in
    different VLANs. The first denial decides. No firewall on the path means allowed.
    """
    firewalls: list[tuple[int, SecurityControl, FirewallConfig]] = []
    segmentations: list[tuple[SecurityControl, SegmentationConfig]] = []
    for control in controls:
        if not control.enabled or control.type in skip_types:
            continue
        if isinstance(control.config, FirewallConfig):
            position = _path_position(control, ctx)
            if position is not None and control.placement.kind == PlacementKind.INLINE:
                firewalls.append((position, control, control.config))
        elif isinstance(control.config, SegmentationConfig) and _segmentation_applies(control, ctx):
            segmentations.append((control, control.config))

    last: tuple[str, int | None, str] | None = None
    reasons: list[str] = []

    if ctx.layer >= catalog.min_layer(ControlType.FIREWALL):
        for _, control, firewall_config in sorted(firewalls, key=lambda item: (item[0], item[1].code)):
            action, rule_index, reason = _firewall_decision(control, firewall_config, ctx)
            if action == RuleAction.DENY:
                return ConnectivityResult(
                    allowed=False,
                    deciding_control_id=control.id,
                    rule_index=rule_index,
                    reason=reason,
                )
            last = (control.id, rule_index, reason)
            reasons.append(reason)

    src_vlan, dst_vlan = ctx.source_asset.vlan, ctx.target_asset.vlan
    if src_vlan is not None and dst_vlan is not None and src_vlan != dst_vlan:
        for control, segmentation_config in sorted(segmentations, key=lambda item: item[0].code):
            action, rule_index, reason = _segmentation_decision(
                control, segmentation_config, src_vlan, dst_vlan
            )
            if action == RuleAction.DENY:
                return ConnectivityResult(
                    allowed=False,
                    deciding_control_id=control.id,
                    rule_index=rule_index,
                    reason=reason,
                )
            last = (control.id, rule_index, reason)
            reasons.append(reason)

    if last is None:
        return ConnectivityResult(allowed=True, reason="no firewall or segmentation rule on the path")
    return ConnectivityResult(
        allowed=True, deciding_control_id=last[0], rule_index=last[1], reason="; ".join(reasons)
    )


def check_flow(
    controls: Sequence[SecurityControl],
    source: Asset,
    target: Asset,
    path_asset_ids: Sequence[str],
    protocol: Protocol,
    port: int,
    layer: int = 7,
) -> ConnectivityResult:
    """Decide whether plain traffic from source to a port on target is allowed along a path.

    The same decision as `check_connectivity`, for callers that have a flow and no
    attack technique, such as reachability analysis.
    """
    context = StepContext(
        technique_id=FLOW,
        source_asset=source,
        target_asset=target,
        path_asset_ids=list(path_asset_ids),
        layer=layer,
        protocol=protocol,
        port=port,
    )
    return check_connectivity(controls, context)
