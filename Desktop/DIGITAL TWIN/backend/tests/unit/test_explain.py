"""Explanation validation, generation, retry and template fallback. Mock provider only."""

import copy
import json
from typing import Any

import pytest
import pytest_asyncio

from app.analysis import risk as risk_module
from app.analysis import service
from app.core.errors import NotFound, ValidationFailed
from app.llm import explain
from app.llm import repository as explanation_repository
from app.llm.client import ProviderError
from app.llm.providers import MockProvider
from app.llm.template import NOT_COVERED, compose_explanation, sources_for_recommendation
from app.llm.validate import cited_ids, containment_words, stated_scores, validate_explanation
from app.models.explanation import EXPLANATION_SCHEMA, ExplanationBody
from app.models.network import Network
from app.rag.documents import IngestSummary
from app.rag.retrieve import retrieve
from app.simulation import engine
from app.twin import repository


@pytest_asyncio.fixture
async def s1(acme_id: str, kb_index: IngestSummary) -> dict[str, Any]:
    """Findings, risk, retrieved sources and context of scenario S1 on the sample network."""
    run = await engine.run(acme_id, "S1")
    findings = await service.findings_for(run)
    risk = risk_module.score_run(findings)
    retrieved = retrieve(explain.build_query(findings), explain.ordered_techniques(findings), explain.RETRIEVE_K)
    return {
        "run": run, "findings": findings, "risk": risk, "retrieved": retrieved,
        "context": explain.build_context(findings, risk, retrieved),
    }


def good(context: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(compose_explanation(context))


def problems(answer: dict[str, Any], context: dict[str, Any]) -> list[str]:
    return validate_explanation(ExplanationBody.model_validate(answer), context)


def test_citation_parsing() -> None:
    assert cited_ids("Poisoning is detectable [S1]. Enable inspection [S3][S12], see also [S1].") == ["S1", "S3", "S12"]
    assert cited_ids("No citations, not [s1], not [S], not [1], not S2.") == []


def test_containment_and_score_parsing() -> None:
    assert containment_words("The run ended objective_reached.") == {"objective_reached"}
    assert containment_words("Objective reached; the attack was not contained.") == {"objective_reached", "contained"}
    assert containment_words("It was partially contained.") == {"partially_contained"}
    assert containment_words("Outcome: contained (containment is good).") == {"contained"}
    assert containment_words("Nothing relevant here.") == set()

    assert stated_scores("a risk score of 39 (medium)") == [39]
    assert stated_scores("The risk score is 41, i.e. 41/100 or 41 out of 100.") == [41, 41, 41]
    assert stated_scores("5 of 5 steps completed after 950 seconds") == []


def test_context_shape(s1: dict[str, Any]) -> None:
    context = s1["context"]
    assert set(context) == {"findings", "risk", "sources", "control_codes"}
    assert context["risk"] == {"score": 39, "band": "medium", "likelihood": 0.53, "impact": 0.7286}
    assert context["findings"]["containment"] == "objective_reached"
    assert context["findings"]["killchain"][0] == {
        "step_order": 1, "tactic": "credential_access", "technique_id": "T1557.002",
        "technique_name": "ARP Cache Poisoning", "outcome": "detected_not_blocked",
    }
    assert [source["id"] for source in context["sources"]] == [f"S{n}" for n in range(1, len(context["sources"]) + 1)]
    assert set(context["sources"][0]) == {"id", "source_name", "source_url", "section_id", "kind", "technique_ids", "text"}
    assert context["control_codes"] == ["FW-INT", "IDS-01", "NAC-01", "SIEM-01", "SWSEC-2"]
    json.dumps(context)
    assert explain.ordered_techniques(s1["findings"]) == ["T1557.002", "T1599", "T1046", "T1190", "T1078"]


def test_good_answer_passes_and_every_recommendation_is_cited(s1: dict[str, Any]) -> None:
    answer = good(s1["context"])
    assert problems(answer, s1["context"]) == []
    assert len(answer["recommendations"]) >= 1
    assert all(len(item["citation_ids"]) >= 1 for item in answer["recommendations"])
    assert "objective_reached" in answer["summary"] and "risk score of 39" in answer["summary"]
    assert len(answer["timeline"]) == 5


def test_validator_rejects_a_wrong_containment_word(s1: dict[str, Any]) -> None:
    answer = good(s1["context"])
    answer["summary"] = answer["summary"].replace("objective_reached", "contained")
    assert problems(answer, s1["context"]) == [
        "summary must state the containment value exactly: objective_reached",
        "summary says 'contained' but the findings say containment is objective_reached",
    ]

    softened = good(s1["context"])
    softened["summary"] += " In the end the attack was partially contained."
    assert problems(softened, s1["context"]) == [
        "summary says 'partially_contained' but the findings say containment is objective_reached"
    ]


def test_validator_rejects_a_changed_risk_score(s1: dict[str, Any]) -> None:
    answer = good(s1["context"])
    answer["summary"] = answer["summary"].replace("risk score of 39", "risk score of 12")
    assert problems(answer, s1["context"]) == [
        "summary must contain the risk score 39",
        "text states a risk score of 12 but the findings say 39",
    ]

    elsewhere = good(s1["context"])
    elsewhere["why_caught_or_missed"] += " That makes the risk score 93/100."
    assert problems(elsewhere, s1["context"]) == ["text states a risk score of 93 but the findings say 39"]


def test_validator_rejects_missing_and_unknown_citations(s1: dict[str, Any]) -> None:
    context = s1["context"]

    uncited = good(context)
    uncited["recommendations"][0]["citation_ids"] = []
    assert "recommendation 1 has no citation" in problems(uncited, context)

    dangling = good(context)
    dangling["summary"] += " ARP poisoning is well documented [S42]."
    assert problems(dangling, context) == ["[S42] is cited but is not in the citations list"]

    in_list_only = good(context)
    in_list_only["timeline"][0]["citation_ids"] = ["S77"]
    assert "[S77] is cited but is not in the citations list" in problems(in_list_only, context)

    invented = good(context)
    invented["citations"].append({"id": "S42", "source_name": "Made-up Handbook", "source_url": "https://example.com"})
    assert problems(invented, context) == ["citation S42 is not one of the provided sources"]

    altered = good(context)
    altered["citations"][0]["source_url"] = "https://example.com/elsewhere"
    assert problems(altered, context) == [
        f"citation {altered['citations'][0]['id']} does not match the name and url of source {altered['citations'][0]['id']}"
    ]


def test_validator_rejects_invented_controls_techniques_and_steps(s1: dict[str, Any]) -> None:
    context = s1["context"]
    answer = good(context)
    answer["recommendations"][0]["related_control_code"] = "FW-QUANTUM"
    answer["recommendations"][0]["related_technique_id"] = "T1486"
    answer["timeline"].append({"step_order": 9, "plain_explanation": "A ninth step happened.", "citation_ids": []})
    assert problems(answer, context) == [
        "recommendation 1 names control FW-QUANTUM, which is not in this network",
        "recommendation 1 names technique T1486, which is not in this run",
        "timeline has step 9, which was not executed",
    ]


def test_schema_and_model_agree() -> None:
    assert EXPLANATION_SCHEMA["required"] == ["summary", "timeline", "why_caught_or_missed", "recommendations", "citations"]
    assert EXPLANATION_SCHEMA["additionalProperties"] is False
    recommendation = EXPLANATION_SCHEMA["properties"]["recommendations"]["items"]
    assert recommendation["properties"]["effort_hint"]["enum"] == ["low", "medium", "high"]
    assert set(recommendation["required"]) == set(ExplanationBody.model_fields["recommendations"].annotation.__args__[0].model_fields)


async def test_mac_spoofing_explanation_cites_attack_and_d3fend(s1: dict[str, Any], offline_ai: MockProvider) -> None:
    explanation = await explain.generate_explanation(s1["findings"], s1["risk"], s1["retrieved"])

    assert (explanation.generated_without_llm, explanation.provider, explanation.attempts) == (False, "mock", 1)
    assert explanation.validation_errors == []
    cited = {citation.id: citation for citation in explanation.citations}
    urls = {citation.source_url for citation in cited.values()}
    names = {citation.source_name for citation in cited.values()}
    assert "https://attack.mitre.org/techniques/T1557/002" in urls
    assert "MITRE D3FEND" in names or "NIST SP 800-53 Rev 5" in names

    first = explanation.recommendations[0]
    assert (first.related_control_code, first.related_technique_id) == ("SWSEC-2", "T1557.002")
    assert "D3-NTA" in first.text and "dynamic_arp_inspection is false on SWSEC-2" in first.text
    assert len(first.citation_ids) == 2
    assert all(recommendation.citation_ids for recommendation in explanation.recommendations)
    assert all(set(recommendation.citation_ids) <= set(cited) for recommendation in explanation.recommendations)
    assert explanation.timeline[0].citation_ids and "[S" in explanation.timeline[0].plain_explanation
    assert len(offline_ai.calls) == 1


async def test_one_bad_answer_is_regenerated_with_the_errors(s1: dict[str, Any]) -> None:
    bad = good(s1["context"])
    bad["summary"] = bad["summary"].replace("risk score of 39", "risk score of 12")
    provider = MockProvider(script=[json.dumps(bad), json.dumps(good(s1["context"]))])

    explanation = await explain.generate_explanation(s1["findings"], s1["risk"], s1["retrieved"], provider=provider)

    assert (explanation.generated_without_llm, explanation.attempts, explanation.provider) == (False, 2, "mock")
    assert explanation.validation_errors == [
        "attempt 1: summary must contain the risk score 39",
        "attempt 1: text states a risk score of 12 but the findings say 39",
    ]
    assert "risk score of 39" in explanation.summary

    assert [len(call) for call in provider.calls] == [1, 3]
    retry = provider.calls[1]
    assert [message.role for message in retry] == ["user", "assistant", "user"]
    assert retry[1].content == json.dumps(bad)
    assert "- text states a risk score of 12 but the findings say 39" in retry[2].content


async def test_two_bad_answers_fall_back_to_a_consistent_template(s1: dict[str, Any]) -> None:
    wrong_word = good(s1["context"])
    wrong_word["summary"] = wrong_word["summary"].replace("objective_reached", "contained")
    wrong_score = good(s1["context"])
    wrong_score["summary"] = wrong_score["summary"].replace("risk score of 39", "risk score of 5")
    provider = MockProvider(script=[json.dumps(wrong_word), json.dumps(wrong_score), "never used"])

    explanation = await explain.generate_explanation(s1["findings"], s1["risk"], s1["retrieved"], provider=provider)

    assert explanation.generated_without_llm is True
    assert (explanation.provider, explanation.model, explanation.attempts) == ("template", "template", 2)
    assert len(provider.calls) == 2 and provider.script == ["never used"]
    assert [error.split(":")[0] for error in explanation.validation_errors] == ["attempt 1", "attempt 1", "attempt 2", "attempt 2"]

    body = ExplanationBody.model_validate(explanation.model_dump(include=set(ExplanationBody.model_fields)))
    assert validate_explanation(body, s1["context"]) == []
    assert "objective_reached" in explanation.summary and "risk score of 39 (medium)" in explanation.summary
    assert "completed 5 of 5 steps" in explanation.summary
    assert [item.step_order for item in explanation.timeline] == [1, 2, 3, 4, 5]
    assert all(recommendation.citation_ids for recommendation in explanation.recommendations)
    assert "dynamic_arp_inspection is false on SWSEC-2" in explanation.why_caught_or_missed


async def test_schema_violations_and_model_errors_also_fall_back(s1: dict[str, Any]) -> None:
    provider = MockProvider(script=['{"summary": "only a summary"}', "not json at all"])
    explanation = await explain.generate_explanation(s1["findings"], s1["risk"], s1["retrieved"], provider=provider)
    assert explanation.generated_without_llm is True
    assert explanation.validation_errors[0].startswith("attempt 1: output does not fit the schema at timeline")
    assert explanation.validation_errors[-1].startswith("attempt 2: model call failed (invalid_json)")

    down = MockProvider(script=[ProviderError("auth", "bad key"), ProviderError("auth", "bad key")])
    offline = await explain.generate_explanation(s1["findings"], s1["risk"], s1["retrieved"], provider=down)
    assert offline.generated_without_llm is True
    assert offline.validation_errors == [
        "attempt 1: model call failed (auth): bad key",
        "attempt 2: model call failed (auth): bad key",
    ]
    assert [len(call) for call in down.calls] == [1, 1]


async def test_no_sources_means_no_recommendations(acme_id: str) -> None:
    run = await engine.run(acme_id, "S1")
    explanation = await explain.explain_run(run.id)
    assert (explanation.recommendations, explanation.citations) == ([], [])
    assert NOT_COVERED in explanation.why_caught_or_missed
    assert "objective_reached" in explanation.summary and "39" in explanation.summary
    assert all(item.citation_ids == [] for item in explanation.timeline)


def test_recommendation_sources_prefer_those_mapped_to_the_technique() -> None:
    sources = [
        {"id": "S1", "kind": "attack", "technique_ids": ["T1110"]},
        {"id": "S2", "kind": "policy", "technique_ids": ["T1110"]},
        {"id": "S3", "kind": "nist", "technique_ids": []},
        {"id": "S4", "kind": "d3fend", "technique_ids": ["T1557.002"]},
    ]
    picked = lambda technique: [source["id"] for source in sources_for_recommendation(technique, sources)]  # noqa: E731
    assert picked("T1557.002") == ["S4"]
    assert picked("T1110") == ["S2"]
    assert picked("T1190") == ["S3"]
    assert sources_for_recommendation("T1190", sources[:2]) == []
    assert [s["id"] for s in sources_for_recommendation("T1110", [sources[0]])] == ["S1"]


async def test_explain_run_caches_and_force_regenerates(acme_id: str, kb_index: IngestSummary, offline_ai: MockProvider) -> None:
    run = await engine.run(acme_id, "S4")
    assert await explanation_repository.get_explanation(run.id) is None

    first = await explain.explain_run(run.id)
    assert (first.run_id, first.network_id) == (run.id, acme_id)
    assert await explanation_repository.get_explanation(run.id) == first
    assert await explain.explain_run(run.id) == first
    assert len(offline_ai.calls) == 1

    forced = await explain.explain_run(run.id, force=True)
    assert len(offline_ai.calls) == 2
    assert forced.id != first.id and forced.summary == first.summary
    assert await explanation_repository.get_explanation(run.id) == forced


async def test_explain_run_errors(database: Any) -> None:
    with pytest.raises(NotFound):
        await explain.explain_run("missing")
    network = await repository.insert_network(Network(name="empty"))
    failed = await engine.run(network.id, "S1")
    with pytest.raises(ValidationFailed, match="no findings"):
        await explain.explain_run(failed.id)


@pytest.mark.parametrize("code", ["S1", "S2", "S3", "S4", "S5", "S6"])
async def test_every_scenario_gets_a_valid_explanation(acme_id: str, kb_index: IngestSummary, code: str) -> None:
    run = await engine.run(acme_id, code)
    explanation = await explain.explain_run(run.id)
    findings = await service.findings_for(run)
    assert findings.containment.value in explanation.summary
    assert str(risk_module.score_run(findings).score) in explanation.summary
    assert len(explanation.timeline) == len(run.step_results)
    assert all(recommendation.citation_ids for recommendation in explanation.recommendations)
    listed = {citation.id for citation in explanation.citations}
    assert all(set(recommendation.citation_ids) <= listed for recommendation in explanation.recommendations)
