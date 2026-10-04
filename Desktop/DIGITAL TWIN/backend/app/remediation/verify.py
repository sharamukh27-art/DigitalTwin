"""Verification: test a remediation's patch on a sandbox copy and guard against regressions.

Nothing here touches the real network. The sandbox is deleted when the test ends.
"""

import logging
from collections.abc import Sequence

from app.analysis import whatif
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.models.enums import FinalOutcome, RemediationStatus
from app.models.remediation import (
    SYSTEM_ACTOR,
    BundleResult,
    Remediation,
    ScenarioOutcome,
    Verification,
    VerificationSide,
)
from app.models.run import DEFAULT_SEED
from app.models.whatif import PatchOp, WhatIfDiff, WhatIfResult, WhatIfSide
from app.remediation import audit, repository
from app.remediation.ranking import priority
from app.simulation import repository as run_repository
from app.twin import repository as twin_repository

logger = logging.getLogger(__name__)

_CLOSED = (RemediationStatus.REJECTED, RemediationStatus.APPLIED, RemediationStatus.APPROVED)
_CONTAINMENT_RANK = {
    FinalOutcome.OBJECTIVE_REACHED: 0,
    FinalOutcome.PARTIALLY_CONTAINED: 1,
    FinalOutcome.CONTAINED: 2,
}


def judge(diff: Sequence[WhatIfDiff], origin_codes: Sequence[str]) -> tuple[bool, list[str]]:
    """Decide whether a patch is verified. Returns (verified, reasons).

    Verified needs all three:
    - an originating scenario's risk strictly decreases or its containment improves
    - no scenario's risk increases
    - no scenario newly reaches its objective
    Each failed condition adds a reason. When verified, the reasons say what improved.
    """
    improved: list[str] = []
    reasons: list[str] = []
    for item in diff:
        better_containment = _CONTAINMENT_RANK[item.containment_after] > _CONTAINMENT_RANK[item.containment_before]
        if item.scenario_code in origin_codes and (item.delta < 0 or better_containment):
            improved.append(
                f"{item.scenario_code} risk {item.risk_before} -> {item.risk_after}, "
                f"{item.containment_before.value} -> {item.containment_after.value}"
            )
        if item.delta > 0:
            reasons.append(f"regression: {item.scenario_code} risk rose from {item.risk_before} to {item.risk_after}")
        if (
            item.containment_after == FinalOutcome.OBJECTIVE_REACHED
            and item.containment_before != FinalOutcome.OBJECTIVE_REACHED
        ):
            reasons.append(f"regression: {item.scenario_code} now reaches its objective")
    if not improved:
        for code in origin_codes:
            origin = next((item for item in diff if item.scenario_code == code), None)
            if origin is not None:
                reasons.append(
                    f"no improvement: {code} risk stayed at {origin.risk_after} and containment "
                    f"stayed {origin.containment_after.value}"
                )
    if reasons:
        return False, reasons
    return True, [f"improved: {item}" for item in improved]


def _side(side: WhatIfSide) -> VerificationSide:
    return VerificationSide(
        per_scenario=[
            ScenarioOutcome(scenario_code=i.scenario_code, risk_score=i.risk_score, containment=i.containment)
            for i in side.per_scenario
        ],
        average_risk=side.posture.average_risk,
        posture_score=side.posture.posture_score,
    )


def to_verification(
    result: WhatIfResult, origin_codes: Sequence[str], network_version: int
) -> tuple[Verification, float]:
    """Turn a what-if result into a verification record and its average risk reduction."""
    verified, reasons = judge(result.diff, origin_codes)
    before, after = _side(result.before), _side(result.after)
    return (
        Verification(
            verified=verified,
            reasons=reasons,
            network_version=network_version,
            seed=result.seed,
            before=before,
            after=after,
            diff=result.diff,
        ),
        round(before.average_risk - after.average_risk, 2),
    )


async def _seed_of(run_id: str) -> int:
    try:
        return (await run_repository.get_run(run_id)).seed
    except NotFound:
        return DEFAULT_SEED


async def verify(remediation_id: str) -> Remediation:
    """Test a remediation on a sandbox and store the outcome on it.

    Clones the network, applies the patch, and runs every scenario before and after
    with the originating run's seed. The remediation becomes `verified` only when
    `judge` accepts the result; otherwise it stays `proposed` with the reasons added
    to its notes. Before/after results and risk_reduction are stored either way.

    Raises Conflict for a remediation that is already rejected or applied.
    """
    current = await repository.get_remediation(remediation_id)
    if current.status in _CLOSED:
        raise Conflict(
            f"Remediation is {current.status.value} and cannot be verified", {"remediation_id": current.id}
        )
    network = await twin_repository.get_network(current.network_id)
    seed = await _seed_of(current.run_id)
    try:
        result = await whatif.whatif(current.network_id, current.patch, None, seed)
    except ValidationFailed as exc:
        problems = "; ".join(exc.details.get("errors", [])) or exc.message
        updated = current.model_copy(
            update={
                "status": RemediationStatus.PROPOSED,
                "verification": None,
                "risk_reduction": None,
                "priority": None,
                "verified_network_version": None,
                "notes": [*current.notes, f"not verified on network version {network.version}: patch could not be applied ({problems})"],
            }
        )
        saved = await repository.save_remediation(updated)
        await audit.record_change(SYSTEM_ACTOR, "remediation.verification_failed", current, saved, problems)
        return saved

    verification, reduction = to_verification(result, [current.scenario_code], network.version)
    outcome = "verified" if verification.verified else "not verified"
    note = f"{outcome} on network version {network.version}: " + "; ".join(verification.reasons)
    updated = current.model_copy(
        update={
            "status": RemediationStatus.VERIFIED if verification.verified else RemediationStatus.PROPOSED,
            "verification": verification,
            "risk_reduction": reduction,
            "priority": priority(reduction, current.effort) if verification.verified else None,
            "verified_network_version": network.version if verification.verified else None,
            "notes": [*current.notes, note],
        }
    )
    saved = await repository.save_remediation(updated)
    action = "remediation.verified" if verification.verified else "remediation.verification_failed"
    await audit.record_change(SYSTEM_ACTOR, action, current, saved, note)
    logger.info("remediation verified" if verification.verified else "remediation not verified",
                extra={"remediation_id": saved.id, "risk_reduction": reduction})
    return saved


async def verify_bundle(remediation_ids: Sequence[str]) -> BundleResult:
    """Apply several remediations together in one sandbox and report the combined effect.

    The patches are applied in the order given. The bundle counts as verified when at
    least one originating scenario improves, nothing regresses and no scenario newly
    reaches its objective. Nothing is stored on the remediations.

    Raises ValidationFailed for remediations of different networks, repeated ids or a
    combined patch that cannot be applied, and Conflict when one is rejected or applied.
    """
    if len(set(remediation_ids)) != len(remediation_ids):
        raise ValidationFailed("A bundle cannot list the same remediation twice", {"ids": list(remediation_ids)})
    members = [await repository.get_remediation(remediation_id) for remediation_id in remediation_ids]
    networks = {member.network_id for member in members}
    if len(networks) != 1:
        raise ValidationFailed("All remediations of a bundle must belong to the same network")
    closed = [member.id for member in members if member.status in _CLOSED]
    if closed:
        raise Conflict("Rejected or applied remediations cannot be bundled", {"remediation_ids": closed})

    network = await twin_repository.get_network(members[0].network_id)
    patch: list[PatchOp] = [op for member in members for op in member.patch]
    seed = await _seed_of(members[0].run_id)
    result = await whatif.whatif(network.id, patch, None, seed)
    origins = list(dict.fromkeys(member.scenario_code for member in members))
    verification, reduction = to_verification(result, origins, network.version)
    return BundleResult(
        remediation_ids=[member.id for member in members],
        network_id=network.id,
        patch=patch,
        verification=verification,
        risk_reduction=reduction,
        individual_risk_reductions={member.id: member.risk_reduction for member in members},
    )
