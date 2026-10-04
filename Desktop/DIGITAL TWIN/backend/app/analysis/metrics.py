"""Findings: plain metrics derived from one simulation run and the twin. No LLM."""

from app.analysis.weakest_link import find_weakest_link, is_blind_spot
from app.controls import catalog
from app.models.analysis import (
    AttackDepth,
    BlastRadius,
    ControlRef,
    Findings,
    KillchainStep,
    MissedControl,
    NotSeenGap,
    TwinSnapshot,
)
from app.models.asset import Asset
from app.models.control import BackupConfig, SecurityControl
from app.models.enums import (
    AssetType,
    ControlOutcome,
    DataClassification,
    EffectKind,
    PlacementKind,
    RunStatus,
    StepOutcome,
)
from app.models.run import SimulationRun, StepResult
from app.scenarios import catalog as scenario_catalog

SENSITIVITY_ORDER: tuple[DataClassification, ...] = (
    DataClassification.PUBLIC,
    DataClassification.INTERNAL,
    DataClassification.CONFIDENTIAL,
    DataClassification.RESTRICTED,
)
_DATA_ASSET_LEVELS = frozenset({DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED})
_DETECTING = (ControlOutcome.DETECTED, ControlOutcome.LOGGED)


def _control_refs(
    steps: list[StepResult], outcomes: tuple[ControlOutcome, ...], names: dict[str, str]
) -> list[ControlRef]:
    """Return each control with one of the outcomes, once, in order of first appearance."""
    seen: list[str] = []
    for step in steps:
        for result in step.control_results:
            if result.outcome in outcomes and result.control_code not in seen:
                seen.append(result.control_code)
    return [ControlRef(code=code, name=names.get(code, code)) for code in seen]


def _blind_spot_note(step: StepResult, controls: dict[str, SecurityControl]) -> str:
    """Describe a blind spot, naming controls that own the capability but could not see the step."""
    note = f"No control was applicable to {step.technique_id} against {step.target_code}."
    near_misses = [
        f"{result.control_code}: {result.reason}"
        for result in step.control_results
        if (control := controls.get(result.control_code)) is not None
        and control.enabled
        and catalog.get_capability(control.type, step.technique_id) is not None
    ]
    if near_misses:
        note += " Controls with the capability that could not see it: " + "; ".join(near_misses) + "."
    return note


def blast_radius(run: SimulationRun, assets: dict[str, Asset]) -> BlastRadius:
    """Return the assets the attacker stood on or successfully acted against.

    The entry asset and attacker nodes are left out. `assets` is keyed by code;
    codes the twin no longer has are skipped.
    """
    entry = run.path_taken[0] if run.path_taken else None
    touched: list[str] = []
    for step in run.step_results:
        if step.outcome == StepOutcome.BLOCKED:
            continue
        for code in (step.target_code, step.position_after):
            asset = assets.get(code or "")
            if (
                asset is not None
                and code != entry
                and asset.type != AssetType.ATTACKER_NODE
                and asset.code not in touched
            ):
                touched.append(asset.code)
    reached = [assets[code] for code in touched]
    levels = [asset.data_classification for asset in reached]
    return BlastRadius(
        asset_codes=touched,
        count=len(touched),
        criticality_sum=sum(asset.criticality for asset in reached),
        max_criticality=max((asset.criticality for asset in reached), default=0),
        data_assets_reached=[
            asset.code for asset in reached if asset.data_classification in _DATA_ASSET_LEVELS
        ],
        max_cvss=max((cve.cvss for asset in reached for cve in asset.known_cves), default=0.0),
        max_data_classification=max(levels, key=SENSITIVITY_ORDER.index) if levels else None,
    )


def has_offline_backup(asset: Asset, controls: list[SecurityControl]) -> bool:
    """Return True when an enabled backup control with offline copies covers the asset."""
    for control in controls:
        if not control.enabled or not isinstance(control.config, BackupConfig):
            continue
        covers = (
            control.placement.kind == PlacementKind.NETWORK_WIDE
            or asset.id in control.placement.asset_ids
        )
        if covers and control.config.offline_copies:
            return True
    return False


def encryption_is_unrecoverable(
    run: SimulationRun, assets: dict[str, Asset], controls: list[SecurityControl]
) -> bool:
    """Return True when data was encrypted on an asset that has no offline backup."""
    for step in run.step_results:
        if EffectKind.ENCRYPT_DATA.value not in step.effects_applied:
            continue
        asset = assets.get(step.target_code or "")
        if asset is None or not has_offline_backup(asset, controls):
            return True
    return False


def compute_findings(run: SimulationRun, twin: TwinSnapshot) -> Findings:
    """Derive findings from a completed run and the twin it ran on.

    Raises ValueError for a run that did not complete.
    """
    if run.status != RunStatus.COMPLETED or run.final_outcome is None:
        raise ValueError(f"run {run.id} did not complete, so it has no findings")

    scenario = scenario_catalog.get(run.scenario_id)
    assets = {asset.code: asset for asset in twin.assets}
    controls = {control.code: control for control in twin.controls}
    names = {control.code: control.name for control in twin.controls}
    steps = run.step_results

    achieved = sum(1 for step in steps if step.outcome != StepOutcome.BLOCKED)
    total = len(scenario.steps)
    first_block = next((s.step_order for s in steps if s.outcome == StepOutcome.BLOCKED), None)

    return Findings(
        run_id=run.id,
        network_id=run.network_id,
        scenario_code=run.scenario_code,
        network_version=run.network_version,
        attacker_profile=scenario.attacker_profile,
        containment=run.final_outcome,
        first_detection_step=run.first_detection.step_order if run.first_detection else None,
        time_to_detect_seconds=run.first_detection.offset_seconds if run.first_detection else None,
        first_block_step=first_block,
        detecting_controls=_control_refs(steps, _DETECTING, names),
        blocking_controls=_control_refs(steps, (ControlOutcome.BLOCKED,), names),
        missed_controls=[
            MissedControl(
                code=result.control_code,
                name=names.get(result.control_code, result.control_code),
                step_order=step.step_order,
                technique_id=step.technique_id,
                reason=result.reason,
            )
            for step in steps
            for result in step.control_results
            if result.outcome == ControlOutcome.MISSED
        ],
        not_seen_gaps=[
            NotSeenGap(
                technique_id=step.technique_id,
                step_order=step.step_order,
                note=_blind_spot_note(step, controls),
            )
            for step in steps
            if is_blind_spot(step)
        ],
        attack_depth=AttackDepth(
            hops_achieved=achieved, total_steps=total, ratio=round(achieved / total, 4) if total else 0.0
        ),
        blast_radius=blast_radius(run, assets),
        effects_gained=run.effects_gained,
        weakest_link=find_weakest_link(steps, controls, assets),
        killchain=[
            KillchainStep(
                step_order=step.step_order,
                tactic=step.tactic,
                technique_id=step.technique_id,
                outcome=step.outcome,
            )
            for step in steps
        ],
        total_network_criticality=sum(asset.criticality for asset in twin.assets),
        unrecoverable_encryption=encryption_is_unrecoverable(run, assets, twin.controls),
    )
