"""Risk math on hand-built findings."""

from typing import Any

import pytest

from app.analysis import risk
from app.models.analysis import AttackDepth, BlastRadius, Findings, KillchainStep
from app.models.enums import RiskBand


def make_findings(
    outcomes: list[str],
    total_steps: int,
    containment: str,
    profile: str,
    blast: dict[str, Any] | None = None,
    effects: list[str] | None = None,
    total_criticality: int = 80,
    unrecoverable: bool = False,
) -> Findings:
    achieved = sum(1 for outcome in outcomes if outcome != "blocked")
    return Findings(
        run_id="run",
        network_id="net",
        scenario_code="T1",
        network_version=1,
        attacker_profile=profile,
        containment=containment,
        attack_depth=AttackDepth(
            hops_achieved=achieved, total_steps=total_steps, ratio=round(achieved / total_steps, 4)
        ),
        blast_radius=BlastRadius(**(blast or {})),
        effects_gained=effects or [],
        killchain=[
            KillchainStep(step_order=index + 1, tactic="initial_access", technique_id="T1190", outcome=outcome)
            for index, outcome in enumerate(outcomes)
        ],
        total_network_criticality=total_criticality,
        unrecoverable_encryption=unrecoverable,
    )


INSIDER_EXFIL = make_findings(
    ["undetected", "undetected"], 2, "objective_reached", "insider",
    blast={"asset_codes": ["FS"], "count": 1, "criticality_sum": 4, "max_criticality": 4,
           "max_cvss": 8.8, "max_data_classification": "confidential"},
    effects=["read_data", "exfiltrate_data"],
)
CONTAINED_OUTSIDER = make_findings(["blocked"], 4, "contained", "outsider")
RANSOMWARE = make_findings(
    ["detected_not_blocked", "undetected", "detected_not_blocked", "undetected"], 4,
    "objective_reached", "compromised_device",
    blast={"asset_codes": ["A", "B"], "count": 2, "criticality_sum": 10, "max_criticality": 5,
           "max_cvss": 10.0, "max_data_classification": "restricted"},
    effects=["encrypt_data"], total_criticality=50, unrecoverable=True,
)
HALFWAY = make_findings(
    ["undetected", "detected_not_blocked", "blocked"], 4, "partially_contained", "outsider",
    blast={"asset_codes": ["W"], "count": 1, "criticality_sum": 2, "max_criticality": 2,
           "max_cvss": 0.0, "max_data_classification": "internal"},
    effects=["gain_foothold"], total_criticality=40,
)


@pytest.mark.parametrize(
    ("findings", "likelihood", "impact", "score", "band"),
    [
        # L = .30*1 + .20*.88 + .15*1.0 + .35*1 ; I = .40*.8 + .25*.05 + .25*.7 + .10*.6
        (INSIDER_EXFIL, 0.976, 0.5675, 55, "high"),
        # L = .15*.6 ; I = .10*.3
        (CONTAINED_OUTSIDER, 0.09, 0.03, 0, "low"),
        # L = .30*.5 + .20*1 + .15*.8 + .35*1 ; I = .40*1 + .25*.2 + .25*1 + .10*1
        (RANSOMWARE, 0.82, 0.8, 66, "high"),
        # L = .30*.25 + 0 + .15*.6 + .35*.5 ; I = .40*.4 + .25*.05 + .25*.4 + .10*.3
        (HALFWAY, 0.34, 0.3025, 10, "low"),
    ],
)
def test_exact_scores(findings: Findings, likelihood: float, impact: float, score: int, band: str) -> None:
    result = risk.score_run(findings)
    assert result.likelihood == pytest.approx(likelihood)
    assert result.impact == pytest.approx(impact)
    assert (result.score, result.band.value) == (score, band)


@pytest.mark.parametrize("findings", [INSIDER_EXFIL, CONTAINED_OUTSIDER, RANSOMWARE, HALFWAY])
def test_breakdown_adds_up_to_the_score(findings: Findings) -> None:
    result = risk.score_run(findings)
    breakdown = result.breakdown
    for factors in (breakdown.likelihood_factors, breakdown.impact_factors):
        assert sum(factor.weight for factor in factors) == pytest.approx(1.0)
        for factor in factors:
            assert factor.contribution == pytest.approx(factor.raw * factor.weight, abs=1e-6)
            assert 0.0 <= factor.raw <= 1.0
            assert factor.detail
    likelihood = sum(factor.contribution for factor in breakdown.likelihood_factors)
    impact = sum(factor.contribution for factor in breakdown.impact_factors)
    assert likelihood == pytest.approx(result.likelihood)
    assert impact == pytest.approx(result.impact)
    assert risk.round_half_up(likelihood * impact * 100) == result.score


def test_breakdown_names_every_factor_and_constant() -> None:
    breakdown = risk.score_run(INSIDER_EXFIL).breakdown
    assert [factor.name for factor in breakdown.likelihood_factors] == [
        "undetected_ratio", "exploit_strength", "profile_factor", "objective_bonus",
    ]
    assert [factor.name for factor in breakdown.impact_factors] == [
        "max_criticality", "criticality_share", "data_sensitivity", "irreversibility",
    ]
    assert {factor.name: factor.weight for factor in breakdown.likelihood_factors} == {
        "undetected_ratio": 0.30, "exploit_strength": 0.20, "profile_factor": 0.15, "objective_bonus": 0.35,
    }
    assert {factor.name: factor.weight for factor in breakdown.impact_factors} == {
        "max_criticality": 0.40, "criticality_share": 0.25, "data_sensitivity": 0.25, "irreversibility": 0.10,
    }
    constants = breakdown.constants
    assert constants["profile_factor"] == {"outsider": 0.6, "compromised_device": 0.8, "insider": 1.0}
    assert constants["data_sensitivity"] == {"restricted": 1.0, "confidential": 0.7, "internal": 0.4, "public": 0.1}
    assert constants["irreversibility"] == {"encrypted_without_offline_backup": 1.0, "exfiltrated": 0.6, "otherwise": 0.3}
    assert constants["band_floors"] == {"critical": 75, "high": 50, "medium": 25, "low": 0}
    assert "round(likelihood x impact x 100)" in breakdown.formula


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, RiskBand.LOW), (24, RiskBand.LOW), (25, RiskBand.MEDIUM), (49, RiskBand.MEDIUM),
        (50, RiskBand.HIGH), (74, RiskBand.HIGH), (75, RiskBand.CRITICAL), (100, RiskBand.CRITICAL),
    ],
)
def test_band_boundaries(score: int, band: RiskBand) -> None:
    assert risk.band_for(score) == band


def test_rounding_is_half_up_at_band_edges() -> None:
    assert risk.round_half_up(24.5) == 25
    assert risk.round_half_up(24.4999) == 24
    assert risk.round_half_up(0.5 * 0.5 * 100) == 25
    assert risk.round_half_up(74.5) == 75
    assert risk.round_half_up(0.29 * 100) == 29


def test_irreversibility_cases() -> None:
    def irreversibility(findings: Findings) -> float:
        return next(f.raw for f in risk.score_run(findings).breakdown.impact_factors if f.name == "irreversibility")

    assert irreversibility(RANSOMWARE) == 1.0
    assert irreversibility(RANSOMWARE.model_copy(update={"unrecoverable_encryption": False})) == 0.3
    assert irreversibility(INSIDER_EXFIL) == 0.6
    assert irreversibility(HALFWAY) == 0.3
    both = RANSOMWARE.model_copy(update={"effects_gained": ["encrypt_data", "exfiltrate_data"]})
    assert irreversibility(both) == 1.0


def test_objective_bonus_uses_depth_when_the_goal_is_not_reached() -> None:
    bonus = next(f for f in risk.score_run(HALFWAY).breakdown.likelihood_factors if f.name == "objective_bonus")
    assert (bonus.raw, bonus.detail) == (0.5, "objective not reached, attack depth 2/4")
    reached = next(f for f in risk.score_run(RANSOMWARE).breakdown.likelihood_factors if f.name == "objective_bonus")
    assert (reached.raw, reached.detail) == (1.0, "objective reached")


def test_worst_case_scores_100_and_empty_network_is_safe() -> None:
    worst = make_findings(
        ["undetected"], 1, "objective_reached", "insider",
        blast={"asset_codes": ["A"], "count": 1, "criticality_sum": 5, "max_criticality": 5,
               "max_cvss": 10.0, "max_data_classification": "restricted"},
        effects=["encrypt_data"], total_criticality=5, unrecoverable=True,
    )
    assert (risk.score_run(worst).score, risk.score_run(worst).band) == (100, RiskBand.CRITICAL)

    nothing = make_findings(["blocked"], 1, "contained", "outsider", total_criticality=0)
    assert risk.score_run(nothing).score == 0
