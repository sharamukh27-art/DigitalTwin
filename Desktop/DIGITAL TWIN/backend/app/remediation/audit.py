"""Audit trail: content hashes and one entry per state change."""

import hashlib
import json

from app.models.remediation import AuditLog, Remediation
from app.remediation import repository
from app.twin import loader

NO_HASH = "-"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def remediation_hash(remediation: Remediation | None) -> str:
    """Hash a remediation's state, ignoring updated_at. A remediation that does not exist yet hashes to "-"."""
    if remediation is None:
        return NO_HASH
    return _digest(remediation.model_dump(mode="json", exclude={"updated_at"}))


async def twin_hash(network_id: str) -> str:
    """Hash a network's exported assets, links and controls."""
    return _digest((await loader.export_network(network_id)).model_dump(mode="json"))


async def record(
    network_id: str,
    actor: str,
    action: str,
    target: str,
    before_hash: str,
    after_hash: str,
    note: str = "",
) -> AuditLog:
    """Write one audit entry."""
    return await repository.insert_audit(
        AuditLog(
            network_id=network_id,
            actor=actor,
            action=action,
            target=target,
            before_hash=before_hash,
            after_hash=after_hash,
            note=note,
        )
    )


async def record_change(
    actor: str, action: str, before: Remediation | None, after: Remediation, note: str = ""
) -> AuditLog:
    """Write an audit entry for a change to a remediation."""
    return await record(
        after.network_id,
        actor,
        action,
        f"remediation:{after.id}",
        remediation_hash(before),
        remediation_hash(after),
        note,
    )
