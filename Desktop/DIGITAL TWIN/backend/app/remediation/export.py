"""Change plan export: the document an administrator follows to apply fixes by hand."""

from collections.abc import Sequence

from app.models.common import utcnow
from app.models.enums import RemediationStatus
from app.models.network import Network
from app.models.remediation import Remediation
from app.remediation.ranking import rank

EXPORTED_STATUSES = (RemediationStatus.VERIFIED, RemediationStatus.APPLIED)


def _risk_lines(remediation: Remediation) -> list[str]:
    verification = remediation.verification
    if verification is None:
        return ["- Expected risk reduction: not measured"]
    lines = [
        f"- Expected risk reduction: {remediation.risk_reduction} points of average risk "
        f"({verification.before.average_risk} -> {verification.after.average_risk}), "
        f"posture {verification.before.posture_score} -> {verification.after.posture_score}"
    ]
    for item in verification.diff:
        if item.delta or item.containment_before != item.containment_after:
            lines.append(
                f"  - {item.scenario_code}: risk {item.risk_before} -> {item.risk_after}, "
                f"{item.containment_before.value} -> {item.containment_after.value}"
            )
    return lines


def render_change_plan(network: Network, remediations: Sequence[Remediation]) -> str:
    """Render the verified and applied remediations of a network as a markdown change plan.

    Verified fixes come first in rank order, then fixes already applied to the twin.
    """
    chosen = rank([item for item in remediations if item.status in EXPORTED_STATUSES])
    lines = [
        f"# Change plan: {network.name}",
        "",
        f"Generated {utcnow().isoformat()} from the digital twin at network version {network.version}.",
        "",
        "Every fix below was tested on a sandbox copy of the twin against all attack scenarios. "
        "Nothing in this plan has been sent to a real device. Apply each change by hand, in your "
        "own change window, and adapt the vendor-neutral snippets to your equipment.",
        "",
        f"Fixes in this plan: {len(chosen)}",
        "",
    ]
    if not chosen:
        lines.append("No verified fixes yet. Generate and verify remediations first.")
    for number, item in enumerate(chosen, start=1):
        devices = ", ".join(item.affected_assets) if item.affected_assets else "none listed"
        if item.status == RemediationStatus.APPLIED:
            state = "applied to the twin"
        elif item.verified_network_version != network.version:
            state = (
                f"verified on network version {item.verified_network_version}; the twin is now at "
                f"version {network.version}, so verify again before approving"
            )
        else:
            state = "verified, awaiting approval"
        lines += [
            f"## {number}. {item.title}",
            "",
            f"- Status: {state}",
            f"- Control: {item.target.code}",
            f"- Affected devices: {devices}",
            f"- Found by: scenario {item.scenario_code}, technique {item.technique_id}",
            f"- Effort: {item.effort.value}",
            *_risk_lines(item),
            "",
            "**Why**",
            "",
            item.rationale,
            "",
            "**Configuration (vendor-neutral)**",
            "",
            "```",
            item.config_snippet,
            "```",
            "",
        ]
        caveats = [note for note in item.notes if note.startswith("caveat: ")]
        if caveats:
            lines += ["**Before you apply**", "", *[f"- {note.removeprefix('caveat: ')}" for note in caveats], ""]
        lines += ["**Sources**", ""]
        if item.citations:
            lines += [f"- [{c.id}] {c.source_name} {c.section_id}: {c.source_url}" for c in item.citations]
        else:
            lines.append("- none: the knowledge base had no source for this fix")
        lines.append("")
    return "\n".join(lines)
