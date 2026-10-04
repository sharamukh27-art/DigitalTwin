"""Human approval: reject a remediation, or approve it and apply its patch to the twin.

"Applied" means applied to the digital twin only. Nothing is ever sent to a real device.
"""

import logging

from app.analysis import posture as posture_module
from app.analysis import whatif
from app.core.errors import Conflict
from app.models.common import utcnow
from app.models.enums import RemediationStatus
from app.models.remediation import Remediation, RemediationUpdate
from app.remediation import audit, repository
from app.scenarios import catalog as scenario_catalog
from app.simulation import engine
from app.simulation import repository as run_repository
from app.twin import repository as twin_repository

logger = logging.getLogger(__name__)

_OPEN = (RemediationStatus.PROPOSED, RemediationStatus.VERIFIED)


async def reject(current: Remediation, actor: str, note: str) -> Remediation:
    """Mark a proposed or verified remediation as rejected and record who and why."""
    if current.status not in _OPEN:
        raise Conflict(
            f"Remediation is {current.status.value} and cannot be rejected", {"remediation_id": current.id}
        )
    updated = current.model_copy(
        update={
            "status": RemediationStatus.REJECTED,
            "notes": [*current.notes, f"rejected by {actor}" + (f": {note}" if note else "")],
        }
    )
    saved = await repository.save_remediation(updated)
    await audit.record_change(actor, "remediation.rejected", current, saved, note)
    return saved


async def approve(current: Remediation, actor: str, note: str) -> Remediation:
    """Approve a verified remediation and apply its patch to the real twin.

    Refused with Conflict unless the remediation is `verified` and was verified on the
    network's current version. The patch is written as one new network version, every
    scenario is re-run on it with the originating run's seed so posture reflects the
    change (a posture snapshot of the new version is stored), and the remediation ends
    as `applied`. Two audit entries are written:
    the approval, and the change to the twin with its before and after hashes.
    """
    if current.status != RemediationStatus.VERIFIED:
        raise Conflict(
            f"Only a verified remediation can be approved; this one is {current.status.value}",
            {"remediation_id": current.id, "status": current.status.value},
        )
    network = await twin_repository.get_network(current.network_id)
    if current.verified_network_version != network.version:
        raise Conflict(
            f"Remediation was verified on network version {current.verified_network_version} but the "
            f"network is now at version {network.version}. Verify it again before approving.",
            {"verified_network_version": current.verified_network_version, "network_version": network.version},
        )

    prepared = await whatif.prepare_patch(network.id, current.patch, require_sandbox=False)
    now = utcnow()
    approved = current.model_copy(
        update={
            "status": RemediationStatus.APPROVED,
            "approved_by": actor,
            "approved_at": now,
            "notes": [*current.notes, f"approved by {actor}" + (f": {note}" if note else "")],
        }
    )
    await audit.record_change(actor, "remediation.approved", current, approved, note)

    before_hash = await audit.twin_hash(network.id)
    new_version = await whatif.write_patch(network.id, prepared)
    after_hash = await audit.twin_hash(network.id)

    applied = approved.model_copy(
        update={
            "status": RemediationStatus.APPLIED,
            "notes": [*approved.notes, f"applied to the twin as network version {new_version}"],
        }
    )
    saved = await repository.save_remediation(applied)
    await audit.record(
        network.id,
        actor,
        "remediation.applied",
        f"network:{network.id}",
        before_hash,
        after_hash,
        f"remediation {saved.id} applied; network version {network.version} -> {new_version}",
    )

    try:
        seed = (await run_repository.get_run(current.run_id)).seed
    except Exception:  # noqa: BLE001 - the originating run may be gone; fall back to the default seed
        seed = engine.DEFAULT_SEED
    for scenario in scenario_catalog.all():
        await engine.run(network.id, scenario.id, seed)
    await posture_module.posture(network.id, refresh=False)
    logger.info("remediation applied to twin", extra={"remediation_id": saved.id, "network_version": new_version})
    return saved


async def decide(remediation_id: str, decision: RemediationUpdate) -> Remediation:
    """Apply a human decision to a remediation."""
    current = await repository.get_remediation(remediation_id)
    if decision.status == "rejected":
        return await reject(current, decision.actor, decision.note)
    return await approve(current, decision.actor, decision.note)
