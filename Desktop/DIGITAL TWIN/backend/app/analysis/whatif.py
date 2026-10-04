"""What-if: compare the twin before and after a patch, on a throwaway sandbox copy.

The real network is never changed and gets no runs. Both sides run on the sandbox
with the same seed, so every difference comes from the patch.
"""

import logging
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from app.analysis import posture as posture_module
from app.analysis import service
from app.controls import repository as control_repository
from app.controls.coverage import coverage
from app.core.errors import Conflict, ValidationFailed
from app.models.asset import Asset
from app.models.common import new_id, utcnow
from app.models.control import SecurityControl, placement_errors
from app.models.enums import PatchTarget, RunStatus
from app.models.link import Link
from app.models.network import Network
from app.models.run import DEFAULT_SEED, SimulationRun
from app.models.scenario import Scenario
from app.models.whatif import (
    PatchOp,
    StepChange,
    WhatIfDiff,
    WhatIfResult,
    WhatIfScenarioState,
    WhatIfSide,
    WhatIfSummary,
)
from app.scenarios import catalog as scenario_catalog
from app.simulation import engine
from app.twin import graph as twin_graph
from app.twin import repository as twin_repository
from app.twin.versioning import bump_version

logger = logging.getLogger(__name__)

PROTECTED_FIELDS = frozenset({"id", "network_id", "code", "type", "created_at", "updated_at"})
ASSET_CODES_PATH = "placement.asset_codes"

TwinPatch = Sequence[PatchOp]
PreparedPatch = tuple[list[Asset], list[SecurityControl], list[SecurityControl]]


async def clone_to_sandbox(network_id: str) -> Network:
    """Copy a network into a new sandbox network and return it.

    Assets, links and controls get fresh ids and keep their codes. The sandbox has
    is_sandbox true, parent_network_id set and the same version as the original.
    """
    original = await twin_repository.get_network(network_id)
    sandbox = Network(
        name=f"{original.name} (sandbox)",
        description=original.description,
        version=original.version,
        parent_network_id=original.id,
        is_sandbox=True,
    )
    now = utcnow()
    fresh = {"network_id": sandbox.id, "created_at": now, "updated_at": now}

    assets = await twin_repository.all_assets(network_id)
    new_ids = {asset.id: new_id() for asset in assets}
    asset_copies = [asset.model_copy(update={"id": new_ids[asset.id], **fresh}) for asset in assets]
    link_copies = [
        link.model_copy(
            update={
                "id": new_id(),
                "source_asset_id": new_ids[link.source_asset_id],
                "target_asset_id": new_ids[link.target_asset_id],
                **fresh,
            }
        )
        for link in await twin_repository.all_links(network_id)
    ]
    control_copies = [
        control.model_copy(
            update={
                "id": new_id(),
                "placement": control.placement.model_copy(
                    update={
                        "asset_ids": [
                            new_ids[asset_id]
                            for asset_id in control.placement.asset_ids
                            if asset_id in new_ids
                        ]
                    }
                ),
                **fresh,
            }
        )
        for control in await control_repository.all_controls(network_id)
    ]

    await twin_repository.insert_network(sandbox)
    try:
        await twin_repository.insert_assets(asset_copies)
        await twin_repository.insert_links(link_copies)
        await control_repository.insert_controls(control_copies)
    except Exception:
        await delete_sandbox(sandbox.id)
        raise
    return sandbox


async def delete_sandbox(sandbox_id: str) -> None:
    """Delete a sandbox with everything it holds, including its runs and findings."""
    await twin_repository.delete_network(sandbox_id)
    twin_graph.evict(sandbox_id)


def _locate(document: dict[str, Any], path: str) -> tuple[Any, Any]:
    """Walk a dotted path and return (container, key) of its last segment.

    Every segment must already exist: dict keys must be present and list segments
    must be valid indexes. Raises ValueError otherwise.
    """
    segments = path.split(".")
    if segments[0] in PROTECTED_FIELDS:
        raise ValueError(f"'{segments[0]}' cannot be changed by a patch")
    node: Any = document
    for position, segment in enumerate(segments):
        if isinstance(node, list):
            if not segment.isdigit() or int(segment) >= len(node):
                raise ValueError(f"unknown path '{path}': no list index '{segment}'")
            key: Any = int(segment)
        elif isinstance(node, dict):
            if segment not in node:
                raise ValueError(f"unknown path '{path}': no field '{segment}'")
            key = segment
        else:
            raise ValueError(f"unknown path '{path}': '{segment}' is below a plain value")
        if position == len(segments) - 1:
            return node, key
        node = node[key]
    raise ValueError(f"unknown path '{path}'")


def set_path(document: dict[str, Any], path: str, value: Any) -> None:
    """Set a value at a dotted path of a nested dict/list structure."""
    container, key = _locate(document, path)
    container[key] = value


def add_to_list(document: dict[str, Any], path: str, value: Any, front: bool = False) -> None:
    """Add a value to the list at a dotted path, unless the list already holds it."""
    container, key = _locate(document, path)
    target = container[key]
    if not isinstance(target, list):
        raise ValueError(f"'{path}' is not a list")
    if value in target:
        return
    if front:
        target.insert(0, value)
    else:
        target.append(value)


def _validation_messages(exc: ValidationError) -> list[str]:
    return [
        ".".join(str(part) for part in error["loc"]) + f": {error['msg']}" if error["loc"] else error["msg"]
        for error in exc.errors()
    ]


def _placement_problems(control: SecurityControl, asset_ids: set[str]) -> list[str]:
    placement = control.placement
    problems = placement_errors(placement.kind, placement.asset_ids, placement.zones, placement.services)
    if any(asset_id not in asset_ids for asset_id in placement.asset_ids):
        problems.append("placement.asset_ids must be assets of this network")
    return problems


def _apply_op(document: dict[str, Any], op: PatchOp, assets: dict[str, Asset]) -> list[str]:
    """Apply the set, append and prepend parts of an op to a document. Returns problems."""
    problems: list[str] = []
    on_control = op.target == PatchTarget.CONTROL
    for path, value in op.set.items():
        try:
            if on_control and path == ASSET_CODES_PATH:
                if not isinstance(value, list) or any(code not in assets for code in value):
                    raise ValueError(f"'{path}' must be a list of asset codes of this network")
                document["placement"]["asset_ids"] = [assets[code].id for code in value]
            else:
                set_path(document, path, value)
        except ValueError as exc:
            problems.append(str(exc))
    for additions, front in ((op.append, False), (op.prepend, True)):
        for path, value in additions.items():
            try:
                if on_control and path == ASSET_CODES_PATH:
                    if value not in assets:
                        raise ValueError(f"'{path}': no asset with code {value} in this network")
                    add_to_list(document, "placement.asset_ids", assets[value].id, front)
                else:
                    add_to_list(document, path, value, front)
            except ValueError as exc:
                problems.append(str(exc))
    return problems


def _create_control(
    network_id: str, op: PatchOp, assets: dict[str, Asset], controls: dict[str, SecurityControl]
) -> tuple[SecurityControl | None, list[str]]:
    """Build the control described by a create op. Returns (control, problems)."""
    if op.code in controls:
        return None, [f"a control with code {op.code} already exists"]
    body = dict(op.create or {})
    placement = dict(body.get("placement") or {})
    codes = placement.pop("asset_codes", [])
    if not isinstance(codes, list) or any(code not in assets for code in codes):
        return None, ["placement.asset_codes must be a list of asset codes of this network"]
    placement["asset_ids"] = [assets[code].id for code in codes]
    try:
        control = SecurityControl.model_validate(
            {**body, "placement": placement, "code": op.code, "network_id": network_id}
        )
    except ValidationError as exc:
        return None, _validation_messages(exc)
    problems = _placement_problems(control, {asset.id for asset in assets.values()})
    return (None, problems) if problems else (control, [])


async def prepare_patch(network_id: str, patch: TwinPatch, require_sandbox: bool = True) -> PreparedPatch:
    """Validate a patch against a network without writing anything.

    Returns the patched assets, the changed controls and the new controls. Ops are
    applied in order, so later ops see the result of earlier ones. Raises
    ValidationFailed listing every problem in the patch. With `require_sandbox`
    (the default) it raises Conflict for a network that is not a sandbox; only the
    remediation approval path turns that off.
    """
    network = await twin_repository.get_network(network_id)
    if require_sandbox and not network.is_sandbox:
        raise Conflict("Patches can only be applied to a sandbox network", {"network_id": network_id})

    assets = {asset.code: asset for asset in await twin_repository.all_assets(network_id)}
    controls = {control.code: control for control in await control_repository.all_controls(network_id)}
    asset_ids = {asset.id for asset in assets.values()}
    created: set[str] = set()
    errors: list[str] = []
    now = utcnow()

    for index, op in enumerate(patch):
        label = f"patch[{index}] ({op.target.value} {op.code})"
        if op.create is not None:
            new_control, problems = _create_control(network_id, op, assets, controls)
            if new_control is not None:
                controls[op.code] = new_control
                created.add(op.code)
            errors.extend(f"{label}: {problem}" for problem in problems)
            continue
        current = (assets if op.target == PatchTarget.ASSET else controls).get(op.code)
        if current is None:
            errors.append(f"{label}: no {op.target.value} with code {op.code}")
            continue
        document = current.model_dump(mode="json")
        problems = _apply_op(document, op, assets)
        if not problems:
            document["updated_at"] = now
            document["created_at"] = current.created_at
            try:
                if op.target == PatchTarget.ASSET:
                    assets[op.code] = Asset.model_validate(document)
                else:
                    patched = SecurityControl.model_validate(document)
                    problems.extend(_placement_problems(patched, asset_ids))
                    if not problems:
                        controls[op.code] = patched
            except ValidationError as exc:
                problems.extend(_validation_messages(exc))
        errors.extend(f"{label}: {problem}" for problem in problems)

    if errors:
        raise ValidationFailed("Patch is not valid. Nothing was changed.", {"errors": errors})
    asset_codes = {op.code for op in patch if op.target == PatchTarget.ASSET}
    control_codes = {op.code for op in patch if op.target == PatchTarget.CONTROL}
    return (
        [assets[code] for code in sorted(asset_codes)],
        [controls[code] for code in sorted(control_codes - created)],
        [controls[code] for code in sorted(created)],
    )


async def write_patch(network_id: str, prepared: PreparedPatch) -> int:
    """Write a prepared patch and bump the network version once. Returns the new version."""
    patched_assets, patched_controls, new_controls = prepared
    for asset in patched_assets:
        await twin_repository.replace_asset(asset)
    for control in patched_controls:
        await control_repository.replace_control(control)
    await control_repository.insert_controls(new_controls)
    return await bump_version(network_id)


async def apply_patch(sandbox_id: str, patch: TwinPatch) -> int:
    """Validate every op of a patch, then apply it to a sandbox. Returns the new version.

    Each patched asset or control is validated against its model, including the
    control's config schema. If any op is invalid nothing is written.
    """
    return await write_patch(sandbox_id, await prepare_patch(sandbox_id, patch))


async def _evaluate(
    sandbox_id: str, scenarios: Sequence[Scenario], seed: int
) -> tuple[WhatIfSide, dict[str, SimulationRun]]:
    """Run the scenarios on the sandbox and score them."""
    network = await twin_repository.get_network(sandbox_id)
    runs: dict[str, SimulationRun] = {}
    risks = []
    for scenario in scenarios:
        run = await engine.run(sandbox_id, scenario.id, seed)
        if run.status != RunStatus.COMPLETED:
            raise ValidationFailed(
                f"Scenario {scenario.code} could not run on this network", {"error": run.error}
            )
        runs[scenario.code] = run
        risks.append(posture_module.scenario_risk(run, await service.findings_for(run)))
    covered = await coverage(sandbox_id)
    side = WhatIfSide(
        per_scenario=[
            WhatIfScenarioState(
                scenario_code=item.scenario_code,
                run_id=item.run_id,
                risk_score=item.risk_score,
                band=item.band,
                containment=item.containment,
            )
            for item in risks
        ],
        posture=posture_module.build_posture(
            sandbox_id, network.version, risks, covered.coverage_percent
        ),
    )
    return side, runs


def step_changes(before: SimulationRun, after: SimulationRun) -> list[StepChange]:
    """Return the steps whose outcome differs between two runs of one scenario."""
    first = {step.step_order: step.outcome for step in before.step_results}
    second = {step.step_order: step.outcome for step in after.step_results}
    return [
        StepChange(step_order=order, from_outcome=first.get(order), to_outcome=second.get(order))
        for order in sorted(set(first) | set(second))
        if first.get(order) != second.get(order)
    ]


def build_diff(
    before: WhatIfSide,
    after: WhatIfSide,
    runs_before: dict[str, SimulationRun],
    runs_after: dict[str, SimulationRun],
) -> tuple[list[WhatIfDiff], WhatIfSummary]:
    """Compare the two sides scenario by scenario."""
    after_by_code = {item.scenario_code: item for item in after.per_scenario}
    diff = [
        WhatIfDiff(
            scenario_code=item.scenario_code,
            risk_before=item.risk_score,
            risk_after=after_by_code[item.scenario_code].risk_score,
            delta=after_by_code[item.scenario_code].risk_score - item.risk_score,
            containment_before=item.containment,
            containment_after=after_by_code[item.scenario_code].containment,
            steps_changed=step_changes(runs_before[item.scenario_code], runs_after[item.scenario_code]),
        )
        for item in before.per_scenario
    ]
    return diff, WhatIfSummary(
        total_risk_delta=sum(item.delta for item in diff),
        scenarios_improved=sum(1 for item in diff if item.delta < 0),
        scenarios_worsened=sum(1 for item in diff if item.delta > 0),
        scenarios_unchanged=sum(1 for item in diff if item.delta == 0),
    )


async def whatif(
    network_id: str,
    patch: TwinPatch,
    scenario_ids: Sequence[str] | None = None,
    seed: int = DEFAULT_SEED,
    keep: bool = False,
) -> WhatIfResult:
    """Compare a network before and after a patch.

    Clones the network to a sandbox, validates the patch, runs the scenarios, applies
    the patch, and runs them again with the same seed. The sandbox is deleted at the
    end unless `keep` is true; it is always deleted when anything fails.
    """
    await twin_repository.get_network(network_id)
    scenarios = (
        [scenario_catalog.get(item) for item in scenario_ids]
        if scenario_ids
        else scenario_catalog.all()
    )
    scenarios = sorted({item.id: item for item in scenarios}.values(), key=lambda item: item.code)

    sandbox = await clone_to_sandbox(network_id)
    try:
        prepared = await prepare_patch(sandbox.id, patch)
        before, runs_before = await _evaluate(sandbox.id, scenarios, seed)
        await write_patch(sandbox.id, prepared)
        after, runs_after = await _evaluate(sandbox.id, scenarios, seed)
    except Exception:
        await delete_sandbox(sandbox.id)
        raise
    if not keep:
        await delete_sandbox(sandbox.id)

    diff, summary = build_diff(before, after, runs_before, runs_after)
    logger.info(
        "what-if completed",
        extra={"network_id": network_id, "total_risk_delta": summary.total_risk_delta, "kept": keep},
    )
    return WhatIfResult(
        network_id=network_id,
        seed=seed,
        patch=list(patch),
        before=before,
        after=after,
        diff=diff,
        summary=summary,
        sandbox_id=sandbox.id if keep else None,
    )
