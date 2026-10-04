"""Deterministic remediation rules: turn the gaps of one run into concrete twin patches.

No LLM is involved. Every candidate is derived from the run's step results, the
capability catalog and the current twin, so the same inputs always give the same fixes.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any

from app.controls import catalog
from app.controls.catalog import Capability
from app.models.analysis import Findings, TwinSnapshot
from app.models.asset import Asset
from app.models.control import (
    BackupConfig,
    FirewallConfig,
    MfaConfig,
    SecurityControl,
    SegmentationConfig,
)
from app.models.enums import (
    AssetType,
    CapabilityAction,
    ControlOutcome,
    ControlType,
    EffectKind,
    EffortHint,
    PatchTarget,
    PlacementKind,
    RemediationRule,
    StepOutcome,
    Zone,
)
from app.models.remediation import Candidate, RemediationTarget
from app.models.run import SimulationRun, StepResult
from app.models.scenario import Scenario, ScenarioStep
from app.models.whatif import PatchOp
from app.remediation import snippets
from app.scenarios import catalog as scenario_catalog
from app.twin import techniques

HIGH_CRITICALITY = 4
_ALLOW_DECISION = re.compile(r"(\S+) rule (\d+) allows")
_FIREWALL_DEFAULT_ALLOW = re.compile(r"(\S+) has no rule for \w+ -> \w+(?: port \d+)?, default action allows")
_SEGMENTATION_DEFAULT_ALLOW = re.compile(r"(\S+) has no rule for VLAN (\d+) -> VLAN (\d+), default action allows")
_APPLICABLE = (
    ControlOutcome.BLOCKED,
    ControlOutcome.DETECTED,
    ControlOutcome.LOGGED,
    ControlOutcome.MISSED,
)


def fingerprint(patch: Sequence[PatchOp]) -> str:
    """Return a stable hash of a patch, used to recognise the same fix twice."""
    canonical = json.dumps([op.model_dump(mode="json") for op in patch], sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class _Context:
    """The twin and scenario a run is judged against."""

    def __init__(self, run: SimulationRun, findings: Findings, twin: TwinSnapshot) -> None:
        self.run = run
        self.findings = findings
        self.scenario: Scenario = scenario_catalog.get(run.scenario_id)
        self.assets: dict[str, Asset] = {asset.code: asset for asset in twin.assets}
        self.asset_codes: dict[str, str] = {asset.id: asset.code for asset in twin.assets}
        self.controls: dict[str, SecurityControl] = {control.code: control for control in twin.controls}

    def scenario_step(self, step: StepResult) -> ScenarioStep:
        return self.scenario.steps[step.step_order - 1]

    def where(self, step: StepResult) -> str:
        technique = techniques.get(step.technique_id)
        return (
            f"In scenario {self.run.scenario_code} step {step.step_order}, {technique.id} "
            f"{technique.name} against {step.target_code}"
        )

    def devices(self, control: SecurityControl) -> list[str]:
        """Return the asset codes a control is placed on."""
        return sorted(self.asset_codes[i] for i in control.placement.asset_ids if i in self.asset_codes)

    def scope(self, control: SecurityControl) -> list[str]:
        """Return where a control acts: its assets, or its zones or services, or the whole network."""
        placement = control.placement
        if placement.kind == PlacementKind.SENSOR:
            return [f"zone {zone.value}" for zone in placement.zones]
        if placement.kind == PlacementKind.IDENTITY:
            return [f"service {service}" for service in placement.services]
        if placement.kind == PlacementKind.NETWORK_WIDE:
            return ["network-wide"]
        return self.devices(control)

    def vlans(self, control: SecurityControl, step: StepResult) -> str:
        """Return the VLANs of the other devices on the step's path, for snippets."""
        own = set(self.devices(control))
        found = {
            self.assets[code].vlan
            for code in step.chosen_path
            if code in self.assets and code not in own and self.assets[code].vlan is not None
        }
        return ",".join(str(vlan) for vlan in sorted(found)) or "<vlan>"  # type: ignore[type-var]


def requirement_ops(control: SecurityControl, capability: Capability) -> tuple[list[PatchOp], list[tuple[str, Any]]]:
    """Return the patch ops that satisfy a capability's `requires`, and what each changes.

    A plain required value is set. A `contains` requirement appends to the list. A
    `not_null` requirement sets the default for that key. Keys already satisfied by
    the control's current config produce nothing.
    """
    values = control.config.model_dump(mode="json")
    to_set: dict[str, Any] = {}
    to_append: list[tuple[str, Any]] = []
    changes: list[tuple[str, Any]] = []
    for key, expected in capability.requires.items():
        actual = values.get(key)
        if isinstance(expected, dict):
            if "contains" in expected and expected["contains"] not in (actual or []):
                to_append.append((key, expected["contains"]))
                changes.append((key, expected["contains"]))
            if expected.get("not_null") and actual is None:
                default = snippets.DEFAULT_VALUES.get((control.type, key))
                if default is not None:
                    to_set[f"config.{key}"] = default
                    changes.append((key, default))
        elif actual != expected:
            to_set[f"config.{key}"] = expected
            changes.append((key, expected))
    ops: list[PatchOp] = []
    if to_set:
        ops.append(PatchOp(target=PatchTarget.CONTROL, code=control.code, set=to_set))
    ops.extend(
        PatchOp(target=PatchTarget.CONTROL, code=control.code, append={f"config.{key}": value})
        for key, value in to_append
    )
    return ops, changes


def _show(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _missed_requirement(ctx: _Context, step: StepResult, control: SecurityControl, capability: Capability, reason: str) -> Candidate | None:
    ops, changes = requirement_ops(control, capability)
    if not ops:
        return None
    titles: list[str] = []
    lines: list[str] = []
    efforts: list[EffortHint] = []
    for key, value in changes:
        title, snippet, effort = snippets.REQUIREMENT_TEXT.get((control.type, key), snippets.GENERIC_REQUIREMENT)
        fields = {"code": control.code, "key": key, "value": _show(value), "vlans": ctx.vlans(control, step)}
        titles.append(title.format(**fields))
        lines.append(snippet.format(**fields))
        efforts.append(effort)
    action, _ = catalog.effective_action(capability, control.config)
    effect = "block" if action == CapabilityAction.BLOCK else action.value
    extra = f" (and {len(titles) - 1} related setting)" if len(titles) > 1 else ""
    return Candidate(
        rule=RemediationRule.MISSED_REQUIREMENT,
        target=RemediationTarget(kind=PatchTarget.CONTROL, code=control.code),
        patch=ops,
        config_snippet="\n".join(lines),
        effort=max(efforts, key=lambda item: list(EffortHint).index(item)),
        technique_id=step.technique_id,
        step_order=step.step_order,
        template_title=titles[0] + extra,
        template_rationale=(
            f"{ctx.where(step)} was missed by {control.code}: {reason}. "
            f"With this change {control.code} can {effect} it."
        ),
        affected_assets=ctx.scope(control),
    )


def _mode_downgrade(ctx: _Context, step: StepResult, control: SecurityControl) -> Candidate | None:
    if control.type not in snippets.BLOCKING_MODE:
        return None
    new_mode, snippet = snippets.BLOCKING_MODE[control.type]
    old_mode = getattr(control.config, "mode").value
    return Candidate(
        rule=RemediationRule.MODE_DOWNGRADE,
        target=RemediationTarget(kind=PatchTarget.CONTROL, code=control.code),
        patch=[PatchOp(target=PatchTarget.CONTROL, code=control.code, set={"config.mode": new_mode})],
        config_snippet=snippet,
        effort=EffortHint.MEDIUM,
        technique_id=step.technique_id,
        step_order=step.step_order,
        template_title=f"Switch {control.code} from {old_mode} to {new_mode} mode",
        template_rationale=(
            f"{ctx.where(step)} was seen by {control.code} but not stopped, because it runs in "
            f"{old_mode} mode. In {new_mode} mode it blocks this technique."
        ),
        affected_assets=ctx.scope(control),
    )


def _placement_gap(ctx: _Context, step: StepResult, control: SecurityControl, capability: Capability) -> Candidate | None:
    """Extend a control's placement so that it sees the step it could have handled."""
    placement = control.placement
    target = ctx.assets.get(step.target_code or "")
    source = ctx.assets.get(step.source_code)
    if target is None or source is None:
        return None
    ops: list[PatchOp] = []
    value: str | None = None

    if placement.kind in (PlacementKind.HOST, PlacementKind.INLINE):
        if target.id not in placement.asset_ids and target.type != AssetType.ATTACKER_NODE:
            value = target.code
            ops.append(PatchOp(target=PatchTarget.CONTROL, code=control.code, append={"placement.asset_codes": value}))
    elif placement.kind == PlacementKind.SENSOR:
        zone = target.zone if target.zone != Zone.INTERNET else source.zone
        if zone != Zone.INTERNET and zone not in placement.zones:
            value = zone.value
            ops.append(PatchOp(target=PatchTarget.CONTROL, code=control.code, append={"placement.zones": value}))
    elif placement.kind == PlacementKind.IDENTITY:
        service = ctx.scenario_step(step).service
        if service is not None:
            additions: dict[str, Any] = {}
            if service not in placement.services:
                additions["placement.services"] = service
            if isinstance(control.config, MfaConfig) and service not in control.config.enforced_for:
                additions["config.enforced_for"] = service
            if additions:
                value = service
                ops.append(PatchOp(target=PatchTarget.CONTROL, code=control.code, append=additions))
    if value is None:
        return None

    known = {json.dumps(op.model_dump(mode="json"), sort_keys=True) for op in ops}
    requirement_fixes, _ = requirement_ops(control, capability)
    for op in requirement_fixes:
        covered = op.append and all(any(existing.append.get(k) == v for existing in ops) for k, v in op.append.items())
        if not covered and json.dumps(op.model_dump(mode="json"), sort_keys=True) not in known:
            ops.append(op)

    title, snippet = snippets.PLACEMENT_TEXT[placement.kind]
    fields = {"code": control.code, "type": control.type.value, "value": value}
    return Candidate(
        rule=RemediationRule.PLACEMENT_GAP,
        target=RemediationTarget(kind=PatchTarget.CONTROL, code=control.code),
        patch=ops,
        config_snippet=snippet.format(**fields),
        effort=EffortHint.MEDIUM,
        technique_id=step.technique_id,
        step_order=step.step_order,
        template_title=title.format(**fields),
        template_rationale=(
            f"{ctx.where(step)} was not seen by {control.code}, which can handle this technique "
            f"but does not cover {value}. Extending it closes that gap."
        ),
        affected_assets=[value] if placement.kind in (PlacementKind.HOST, PlacementKind.INLINE) else ctx.scope(control),
    )


def _new_control(ctx: _Context, step: StepResult) -> Candidate | None:
    """Propose a new control when no control in the network could block the technique."""
    blockers = {
        control_type: capability
        for control_type in ControlType
        if (capability := catalog.get_capability(control_type, step.technique_id)) is not None
        and capability.action == CapabilityAction.BLOCK
    }
    present = {control.type for control in ctx.controls.values() if control.enabled}
    if not blockers or present & set(blockers):
        return None
    control_type = max(blockers, key=lambda item: (blockers[item].confidence, item.value))
    if control_type not in snippets.NEW_CONTROL_DEFAULTS:
        return None
    kind, config = snippets.NEW_CONTROL_DEFAULTS[control_type]
    target = ctx.assets.get(step.target_code or "")
    source = ctx.assets.get(step.source_code)
    service = ctx.scenario_step(step).service
    placement: dict[str, Any] = {"kind": kind.value}
    if kind in (PlacementKind.HOST, PlacementKind.INLINE):
        if target is None or target.type == AssetType.ATTACKER_NODE:
            return None
        placement["asset_codes"] = [target.code]
    elif kind == PlacementKind.SENSOR:
        zones = {asset.zone.value for asset in (source, target) if asset is not None and asset.zone != Zone.INTERNET}
        if not zones:
            return None
        placement["zones"] = sorted(zones)
    elif kind == PlacementKind.IDENTITY:
        if service is None:
            return None
        placement["services"] = [service]
        if control_type == ControlType.MFA:
            config = {**config, "enforced_for": [service]}

    prefix = snippets.NEW_CONTROL_CODES[control_type]
    number = 1
    while f"{prefix}-{number:02d}" in ctx.controls:
        number += 1
    code = f"{prefix}-{number:02d}"
    name = snippets.NEW_CONTROL_NAMES[control_type]
    settings = ", ".join(f"{key}={_show(value)}" for key, value in config.items())
    technique = techniques.get(step.technique_id)
    return Candidate(
        rule=RemediationRule.NEW_CONTROL,
        target=RemediationTarget(kind=PatchTarget.CONTROL, code=code),
        patch=[
            PatchOp(
                target=PatchTarget.CONTROL,
                code=code,
                create={"name": name, "type": control_type.value, "enabled": True, "placement": placement, "config": config},
            )
        ],
        config_snippet=f"deploy {name.lower()} ({control_type.value})\nplacement: {kind.value}\nsettings: {settings}",
        effort=EffortHint.HIGH,
        technique_id=step.technique_id,
        step_order=step.step_order,
        template_title=f"Add a {name.lower()} control to block {technique.name}",
        template_rationale=(
            f"{ctx.where(step)} was not blocked, and no control in this network is able to block "
            f"{technique.id}. A {control_type.value} control can."
        ),
        affected_assets=placement.get("asset_codes", []),
        caveats=[snippets.NEW_CONTROL_CAVEAT],
    )


def _offline_backup(ctx: _Context, step: StepResult) -> Candidate | None:
    asset = ctx.assets.get(step.target_code or "")
    backups = [c for c in ctx.controls.values() if c.enabled and isinstance(c.config, BackupConfig)]
    if asset is None or not backups:
        return None
    covering = [
        c for c in backups if c.placement.kind == PlacementKind.NETWORK_WIDE or asset.id in c.placement.asset_ids
    ]
    if any(c.config.offline_copies for c in covering):  # type: ignore[union-attr]
        return None
    control = sorted(covering or backups, key=lambda item: item.code)[0]
    ops = [PatchOp(target=PatchTarget.CONTROL, code=control.code, set={"config.offline_copies": True})]
    if not covering:
        ops.append(PatchOp(target=PatchTarget.CONTROL, code=control.code, append={"placement.asset_codes": asset.code}))
    devices = sorted({*ctx.devices(control), asset.code})
    return Candidate(
        rule=RemediationRule.OFFLINE_BACKUP,
        target=RemediationTarget(kind=PatchTarget.CONTROL, code=control.code),
        patch=ops,
        config_snippet=snippets.BACKUP_SNIPPET.format(assets=", ".join(devices)),
        effort=EffortHint.MEDIUM,
        technique_id=step.technique_id,
        step_order=step.step_order,
        template_title=f"Keep an offline backup copy for {asset.code}",
        template_rationale=(
            f"{ctx.where(step)} encrypted data that has no offline backup, so the loss would be "
            f"permanent. An offline or immutable copy on {control.code} makes it recoverable. "
            "This lowers the impact; it does not stop the attack."
        ),
        affected_assets=devices,
    )


def _connectivity_holes(ctx: _Context, step: StepResult) -> list[Candidate]:
    """Propose a deny rule for each broad allow decision that let the step through.

    Only steps that reach an asset of criticality 4 or 5, or leave for the internet,
    are considered. A decision is broad when it is a firewall rule with no ports or an
    `any` zone, a firewall's default allow, or a segmentation control's default allow.
    """
    connectivity = step.connectivity
    source, target = ctx.assets.get(step.source_code), ctx.assets.get(step.target_code or "")
    planned = ctx.scenario_step(step)
    if connectivity is None or not connectivity.allowed or source is None or target is None:
        return []
    outbound = target.zone == Zone.INTERNET and source.zone != Zone.INTERNET
    if target.criticality < HIGH_CRITICALITY and not outbound:
        return []
    where = ctx.where(step)
    found: list[Candidate] = []

    broad_firewalls: list[tuple[SecurityControl, str, str]] = []
    for code, index_text in _ALLOW_DECISION.findall(connectivity.reason):
        control = ctx.controls.get(code)
        index = int(index_text)
        if control is None or not isinstance(control.config, FirewallConfig) or index >= len(control.config.rules):
            continue
        rule = control.config.rules[index]
        if not rule.ports or "any" in (rule.src_zone, rule.dst_zone):
            limit = "ports" if not rule.ports else "zones"
            broad_firewalls.append((control, f"rule {index}, a broad rule that does not limit {limit}", f"rule {index}"))
    for code in _FIREWALL_DEFAULT_ALLOW.findall(connectivity.reason):
        control = ctx.controls.get(code)
        if control is not None and isinstance(control.config, FirewallConfig):
            broad_firewalls.append((control, "its default allow action", "the default action"))

    if planned.port is not None:
        flow = f"{source.zone.value} to {target.zone.value} on port {planned.port}"
        deny = {
            "src_zone": source.zone.value,
            "dst_zone": target.zone.value,
            "ports": [planned.port],
            "protocol": planned.protocol.value,
            "action": "deny",
        }
        for control, description, position in broad_firewalls:
            found.append(
                Candidate(
                    rule=RemediationRule.CONNECTIVITY_HOLE,
                    target=RemediationTarget(kind=PatchTarget.CONTROL, code=control.code),
                    patch=[PatchOp(target=PatchTarget.CONTROL, code=control.code, prepend={"config.rules": deny})],
                    config_snippet=snippets.FIREWALL_DENY_SNIPPET.format(
                        protocol=planned.protocol.value, src=source.zone.value, dst=target.zone.value,
                        port=planned.port, position=position, code=control.code,
                    ),
                    effort=EffortHint.HIGH,
                    technique_id=step.technique_id,
                    step_order=step.step_order,
                    template_title=f"Deny {flow} at {control.code}",
                    template_rationale=(
                        f"{where} was allowed by {control.code} through {description}. "
                        f"A deny rule for {flow} ahead of it stops this path."
                    ),
                    affected_assets=ctx.scope(control),
                    caveats=[snippets.CONNECTIVITY_CAVEAT],
                )
            )

    for code, src_vlan, dst_vlan in _SEGMENTATION_DEFAULT_ALLOW.findall(connectivity.reason):
        control = ctx.controls.get(code)
        if control is None or not isinstance(control.config, SegmentationConfig):
            continue
        rule = {"src_vlan": int(src_vlan), "dst_vlan": int(dst_vlan), "action": "deny"}
        found.append(
            Candidate(
                rule=RemediationRule.CONNECTIVITY_HOLE,
                target=RemediationTarget(kind=PatchTarget.CONTROL, code=control.code),
                patch=[PatchOp(target=PatchTarget.CONTROL, code=control.code, prepend={"config.vlan_rules": rule})],
                config_snippet=f"deny traffic from VLAN {src_vlan} to VLAN {dst_vlan}\n# default action on {control.code} stays allow",
                effort=EffortHint.HIGH,
                technique_id=step.technique_id,
                step_order=step.step_order,
                template_title=f"Deny VLAN {src_vlan} to VLAN {dst_vlan} at {control.code}",
                template_rationale=(
                    f"{where} crossed from VLAN {src_vlan} to VLAN {dst_vlan} because {control.code} "
                    "has no rule for that pair and allows by default. A deny rule separates them."
                ),
                affected_assets=ctx.scope(control),
                caveats=[snippets.CONNECTIVITY_CAVEAT],
            )
        )
    return found


def generate_candidates(run: SimulationRun, findings: Findings, twin: TwinSnapshot) -> list[Candidate]:
    """Return one candidate fix per gap found in a run, in step order, without duplicates.

    Rules, applied to every step the attacker got through:
    - missed_requirement: a control missed the step because of its config.
    - mode_downgrade: a control saw the step but its mode kept it from blocking.
    - placement_gap: a control that can handle the technique did not cover the step,
      and no other control of its type did.
    - new_control: no control in the network is able to block the technique.
    - offline_backup: data was encrypted on an asset with no offline backup.
    - connectivity_hole: a broad allow rule, or no rule at all, let the step reach a
      critical asset or the internet.

    Fixes are computed against the twin as it is now, so a gap that has since been
    closed produces nothing.
    """
    ctx = _Context(run, findings, twin)
    candidates: list[Candidate] = []
    for step in run.step_results:
        if step.outcome == StepOutcome.BLOCKED:
            continue
        applicable_types = {
            ctx.controls[result.control_code].type
            for result in step.control_results
            if result.outcome in _APPLICABLE and result.control_code in ctx.controls
        }
        for result in step.control_results:
            control = ctx.controls.get(result.control_code)
            if control is None or not control.enabled:
                continue
            capability = catalog.get_capability(control.type, step.technique_id)
            if capability is None:
                continue
            found: Candidate | None = None
            if result.outcome == ControlOutcome.MISSED:
                found = _missed_requirement(ctx, step, control, capability, result.reason)
            elif result.outcome == ControlOutcome.DETECTED:
                _, downgraded_from = catalog.effective_action(capability, control.config)
                if downgraded_from is not None:
                    found = _mode_downgrade(ctx, step, control)
            elif result.outcome == ControlOutcome.NOT_APPLICABLE and control.type not in applicable_types:
                found = _placement_gap(ctx, step, control, capability)
            if found is not None:
                candidates.append(found)

        created = _new_control(ctx, step)
        if created is not None:
            candidates.append(created)
        if findings.unrecoverable_encryption and EffectKind.ENCRYPT_DATA.value in step.effects_applied:
            backup = _offline_backup(ctx, step)
            if backup is not None:
                candidates.append(backup)
        candidates.extend(_connectivity_holes(ctx, step))

    unique: dict[str, Candidate] = {}
    for candidate in candidates:
        unique.setdefault(fingerprint(candidate.patch), candidate)
    return list(unique.values())
