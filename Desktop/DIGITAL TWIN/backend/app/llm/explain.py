"""Grounded explanations: retrieve sources, ask the model, validate, fall back to a template.

The model only writes prose. Every value it is given comes from the deterministic
findings, and its answer is checked against them before it is stored.
"""

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from app.analysis import risk as risk_module
from app.analysis import service as analysis_service
from app.llm import repository as explanation_repository
from app.llm.client import LLMMessage, Provider, complete, get_provider
from app.llm.prompts import SYSTEM_PROMPT, render_context, render_retry
from app.llm.template import compose_explanation
from app.llm.validate import validate_explanation
from app.models.analysis import Findings, RiskScore
from app.models.enums import WeakestLinkKind
from app.models.explanation import EXPLANATION_SCHEMA, Explanation, ExplanationBody
from app.rag.documents import RetrievedChunk
from app.rag.retrieve import retrieve
from app.simulation import repository as run_repository
from app.twin import techniques

logger = logging.getLogger(__name__)

RETRIEVE_K = 6
MAX_GENERATIONS = 2
TEMPLATE_PROVIDER = "template"


def ordered_techniques(findings: Findings) -> list[str]:
    """Return the run's technique ids without repeats, the weakest link's technique first."""
    ordered = [step.technique_id for step in findings.killchain]
    link = findings.weakest_link
    if link is not None:
        first = next((s.technique_id for s in findings.killchain if s.step_order == link.step_order), None)
        if first is not None:
            ordered.insert(0, first)
    return list(dict.fromkeys(ordered))


def build_query(findings: Findings) -> str:
    """Build the retrieval query: technique names plus what failed."""
    parts = [techniques.get(technique_id).name for technique_id in ordered_techniques(findings)]
    if findings.weakest_link is not None:
        parts.append(findings.weakest_link.explanation)
    parts.extend(missed.reason for missed in findings.missed_controls)
    parts.append("detection mitigation hardening")
    return " ".join(parts)


def build_context(
    findings: Findings, risk: RiskScore, retrieved: Sequence[RetrievedChunk]
) -> dict[str, Any]:
    """Build the compact JSON block given to the model.

    `findings` and `risk` hold the engine's values. `sources` is the numbered list
    S1..Sn the model may cite. `control_codes` lists the controls named in the
    findings, the only ones a recommendation may refer to.
    """
    link = findings.weakest_link
    control_codes = [
        *(item.code for item in findings.detecting_controls),
        *(item.code for item in findings.blocking_controls),
        *(item.code for item in findings.missed_controls),
        *([link.ref] if link is not None and link.kind == WeakestLinkKind.MISSED_CONTROL else []),
    ]
    blast = findings.blast_radius
    return {
        "findings": {
            "scenario_code": findings.scenario_code,
            "attacker_profile": findings.attacker_profile.value,
            "containment": findings.containment.value,
            "first_detection_step": findings.first_detection_step,
            "time_to_detect_seconds": findings.time_to_detect_seconds,
            "first_block_step": findings.first_block_step,
            "detecting_controls": [item.model_dump() for item in findings.detecting_controls],
            "blocking_controls": [item.model_dump() for item in findings.blocking_controls],
            "missed_controls": [item.model_dump() for item in findings.missed_controls],
            "not_seen_gaps": [item.model_dump() for item in findings.not_seen_gaps],
            "attack_depth": findings.attack_depth.model_dump(),
            "blast_radius": {
                "asset_codes": blast.asset_codes,
                "count": blast.count,
                "max_criticality": blast.max_criticality,
                "data_assets_reached": blast.data_assets_reached,
            },
            "effects_gained": findings.effects_gained,
            "weakest_link": link.model_dump(mode="json") if link is not None else None,
            "killchain": [
                {
                    "step_order": step.step_order,
                    "tactic": step.tactic.value,
                    "technique_id": step.technique_id,
                    "technique_name": techniques.get(step.technique_id).name,
                    "outcome": step.outcome.value,
                }
                for step in findings.killchain
            ],
        },
        "risk": {
            "score": risk.score,
            "band": risk.band.value,
            "likelihood": risk.likelihood,
            "impact": risk.impact,
        },
        "sources": [
            {
                "id": f"S{index}",
                "source_name": chunk.source_name,
                "source_url": chunk.source_url,
                "section_id": chunk.section_id,
                "kind": chunk.kind.value,
                "technique_ids": chunk.technique_ids,
                "text": chunk.text,
            }
            for index, chunk in enumerate(retrieved, start=1)
        ],
        "control_codes": sorted(set(control_codes)),
    }


def _parse(data: dict[str, Any] | None) -> tuple[ExplanationBody | None, list[str]]:
    """Parse model output into the explanation schema. Returns (body, errors)."""
    try:
        return ExplanationBody.model_validate(data), []
    except ValidationError as exc:
        return None, [
            f"output does not fit the schema at {'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        ]


async def generate_explanation(
    findings: Findings,
    risk: RiskScore,
    retrieved: Sequence[RetrievedChunk],
    provider: Provider | None = None,
) -> Explanation:
    """Produce an explanation that is consistent with the findings.

    The model is asked once. If its answer fails validation (or the call fails), it is
    asked once more with the problems listed. If that also fails, a deterministic
    template built from the findings is returned with generated_without_llm true.
    An explanation that contradicts the findings is never returned.
    """
    backend = provider or get_provider()
    context = build_context(findings, risk, retrieved)
    messages = [LLMMessage(role="user", content=render_context(context))]
    problems: list[str] = []

    for attempt in range(1, MAX_GENERATIONS + 1):
        result = await complete(SYSTEM_PROMPT, messages, json_schema=EXPLANATION_SCHEMA, provider=backend)
        if result.ok:
            body, errors = _parse(result.data)
            if body is not None:
                errors = validate_explanation(body, context)
        else:
            body = None
            errors = [f"model call failed ({result.error.kind}): {result.error.message}" if result.error else "model call failed"]
        if body is not None and not errors:
            return Explanation(
                **body.model_dump(),
                run_id=findings.run_id,
                network_id=findings.network_id,
                provider=result.provider,
                model=result.model,
                attempts=attempt,
                validation_errors=problems,
            )
        problems.extend(f"attempt {attempt}: {error}" for error in errors)
        logger.warning(
            "explanation rejected", extra={"run_id": findings.run_id, "attempt": attempt, "problems": errors}
        )
        if result.text:
            messages.append(LLMMessage(role="assistant", content=result.text))
            messages.append(LLMMessage(role="user", content=render_retry(errors)))

    template = ExplanationBody.model_validate(compose_explanation(context))
    template_errors = validate_explanation(template, context)
    if template_errors:
        raise RuntimeError(f"template explanation failed validation: {template_errors}")
    return Explanation(
        **template.model_dump(),
        run_id=findings.run_id,
        network_id=findings.network_id,
        generated_without_llm=True,
        provider=TEMPLATE_PROVIDER,
        model=TEMPLATE_PROVIDER,
        attempts=MAX_GENERATIONS,
        validation_errors=problems,
    )


async def explain_run(run_id: str, force: bool = False) -> Explanation:
    """Return the explanation of a run, generating and caching it when needed.

    Raises NotFound for an unknown run and ValidationFailed for a run that did not
    complete. With `force`, a stored explanation is regenerated and replaced.
    """
    run = await run_repository.get_run(run_id)
    findings = await analysis_service.findings_for(run)
    if not force:
        cached = await explanation_repository.get_explanation(run_id)
        if cached is not None:
            return cached
    risk = risk_module.score_run(findings)
    retrieved = await asyncio.to_thread(
        retrieve, build_query(findings), ordered_techniques(findings), RETRIEVE_K
    )
    explanation = await generate_explanation(findings, risk, retrieved)
    return await explanation_repository.save_explanation(explanation)
