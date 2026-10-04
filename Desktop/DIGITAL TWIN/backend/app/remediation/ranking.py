"""Ranking: which verified fix gives the most risk reduction for the least effort."""

from collections.abc import Sequence

from app.models.enums import EffortHint, RemediationStatus
from app.models.remediation import EFFORT_WEIGHT, Remediation


def priority(risk_reduction: float, effort: EffortHint) -> float:
    """Return risk reduction divided by effort weight (low 1, medium 2, high 3)."""
    return round(risk_reduction / EFFORT_WEIGHT[effort], 4)


def rank(remediations: Sequence[Remediation]) -> list[Remediation]:
    """Order remediations for display.

    Verified ones come first, highest priority first. The rest follow in the order
    they were created.
    """
    verified = [item for item in remediations if item.status == RemediationStatus.VERIFIED]
    others = [item for item in remediations if item.status != RemediationStatus.VERIFIED]
    verified.sort(key=lambda item: (-(item.priority or 0.0), item.created_at, item.id))
    others.sort(key=lambda item: (item.created_at, item.id))
    return verified + others
