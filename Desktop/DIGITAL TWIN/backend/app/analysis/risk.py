"""Risk score with a visible formula: score = round(likelihood x impact x 100)."""

import math

from app.models.analysis import Findings, RiskBreakdown, RiskFactor, RiskScore
from app.models.enums import (
    AttackerProfile,
    DataClassification,
    EffectKind,
    FinalOutcome,
    RiskBand,
    StepOutcome,
)

LIKELIHOOD_WEIGHTS: dict[str, float] = {
    "undetected_ratio": 0.30,
    "exploit_strength": 0.20,
    "profile_factor": 0.15,
    "objective_bonus": 0.35,
}
IMPACT_WEIGHTS: dict[str, float] = {
    "max_criticality": 0.40,
    "criticality_share": 0.25,
    "data_sensitivity": 0.25,
    "irreversibility": 0.10,
}
PROFILE_FACTOR: dict[AttackerProfile, float] = {
    AttackerProfile.OUTSIDER: 0.6,
    AttackerProfile.COMPROMISED_DEVICE: 0.8,
    AttackerProfile.INSIDER: 1.0,
}
DATA_SENSITIVITY: dict[DataClassification, float] = {
    DataClassification.RESTRICTED: 1.0,
    DataClassification.CONFIDENTIAL: 0.7,
    DataClassification.INTERNAL: 0.4,
    DataClassification.PUBLIC: 0.1,
}
IRREVERSIBILITY: dict[str, float] = {
    "encrypted_without_offline_backup": 1.0,
    "exfiltrated": 0.6,
    "otherwise": 0.3,
}
BAND_FLOORS: tuple[tuple[int, RiskBand], ...] = (
    (75, RiskBand.CRITICAL),
    (50, RiskBand.HIGH),
    (25, RiskBand.MEDIUM),
    (0, RiskBand.LOW),
)
MAX_CRITICALITY = 5
MAX_CVSS = 10.0
FORMULA = (
    "likelihood = sum of likelihood contributions; impact = sum of impact contributions; "
    "contribution = raw x weight; score = round(likelihood x impact x 100)"
)


def round_half_up(value: float) -> int:
    """Round to the nearest integer, halves up, after removing float noise."""
    return math.floor(round(value, 6) + 0.5)


def band_for(score: int) -> RiskBand:
    """Return the band of a score: 0-24 low, 25-49 medium, 50-74 high, 75-100 critical."""
    return next(band for floor, band in BAND_FLOORS if score >= floor)


def _factor(name: str, raw: float, weights: dict[str, float], detail: str) -> RiskFactor:
    raw = round(min(max(raw, 0.0), 1.0), 4)
    return RiskFactor(
        name=name, raw=raw, weight=weights[name], contribution=round(raw * weights[name], 6), detail=detail
    )


def likelihood_factors(findings: Findings) -> list[RiskFactor]:
    """Return the four likelihood terms."""
    total = findings.attack_depth.total_steps
    undetected = sum(1 for step in findings.killchain if step.outcome == StepOutcome.UNDETECTED)
    reached = findings.containment == FinalOutcome.OBJECTIVE_REACHED
    blast = findings.blast_radius
    profile = findings.attacker_profile
    return [
        _factor(
            "undetected_ratio",
            undetected / total if total else 0.0,
            LIKELIHOOD_WEIGHTS,
            f"{undetected} undetected steps of {total}",
        ),
        _factor(
            "exploit_strength",
            blast.max_cvss / MAX_CVSS,
            LIKELIHOOD_WEIGHTS,
            f"highest CVSS on reached assets {blast.max_cvss} / {MAX_CVSS}",
        ),
        _factor(
            "profile_factor",
            PROFILE_FACTOR[profile],
            LIKELIHOOD_WEIGHTS,
            f"attacker profile {profile.value}",
        ),
        _factor(
            "objective_bonus",
            1.0 if reached else findings.attack_depth.ratio,
            LIKELIHOOD_WEIGHTS,
            "objective reached"
            if reached
            else f"objective not reached, attack depth {findings.attack_depth.hops_achieved}/{total}",
        ),
    ]


def impact_factors(findings: Findings) -> list[RiskFactor]:
    """Return the four impact terms."""
    blast = findings.blast_radius
    total = findings.total_network_criticality
    level = blast.max_data_classification
    if findings.unrecoverable_encryption:
        irreversibility, why = "encrypted_without_offline_backup", "data encrypted with no offline backup"
    elif EffectKind.EXFILTRATE_DATA.value in findings.effects_gained:
        irreversibility, why = "exfiltrated", "data exfiltrated"
    else:
        irreversibility, why = "otherwise", "no encryption or exfiltration"
    return [
        _factor(
            "max_criticality",
            blast.max_criticality / MAX_CRITICALITY,
            IMPACT_WEIGHTS,
            f"highest criticality reached {blast.max_criticality} / {MAX_CRITICALITY}",
        ),
        _factor(
            "criticality_share",
            blast.criticality_sum / total if total else 0.0,
            IMPACT_WEIGHTS,
            f"criticality reached {blast.criticality_sum} of network total {total}",
        ),
        _factor(
            "data_sensitivity",
            DATA_SENSITIVITY[level] if level is not None else 0.0,
            IMPACT_WEIGHTS,
            f"most sensitive data reached: {level.value}" if level is not None else "no asset reached",
        ),
        _factor("irreversibility", IRREVERSIBILITY[irreversibility], IMPACT_WEIGHTS, why),
    ]


def score_run(findings: Findings) -> RiskScore:
    """Score one run from its findings alone.

    Every weight and lookup value used is returned in `breakdown`, so the full math
    can be shown and re-computed by the caller.
    """
    likelihood_terms = likelihood_factors(findings)
    impact_terms = impact_factors(findings)
    likelihood = round(sum(term.contribution for term in likelihood_terms), 6)
    impact = round(sum(term.contribution for term in impact_terms), 6)
    score = min(100, max(0, round_half_up(likelihood * impact * 100)))
    return RiskScore(
        score=score,
        band=band_for(score),
        likelihood=likelihood,
        impact=impact,
        breakdown=RiskBreakdown(
            likelihood_factors=likelihood_terms,
            impact_factors=impact_terms,
            formula=FORMULA,
            constants={
                "likelihood_weights": LIKELIHOOD_WEIGHTS,
                "impact_weights": IMPACT_WEIGHTS,
                "profile_factor": {profile.value: value for profile, value in PROFILE_FACTOR.items()},
                "data_sensitivity": {level.value: value for level, value in DATA_SENSITIVITY.items()},
                "irreversibility": IRREVERSIBILITY,
                "max_criticality": MAX_CRITICALITY,
                "max_cvss": MAX_CVSS,
                "band_floors": {band.value: floor for floor, band in BAND_FLOORS},
            },
        ),
    )
