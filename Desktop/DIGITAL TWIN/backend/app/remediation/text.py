"""Human text for a remediation: title and rationale. The LLM never sees or changes the patch."""

import json
import logging
from collections.abc import Sequence
from typing import Any

from app.llm.client import LLMMessage, Provider, complete, get_provider
from app.llm.validate import cited_ids
from app.models.remediation import Candidate, RemediationCitation

logger = logging.getLogger(__name__)

TEMPLATE = "template"
MAX_TITLE = 140
MAX_RATIONALE = 1200

TEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"title": {"type": "string"}, "rationale": {"type": "string"}},
    "required": ["title", "rationale"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = (
    "You write the title and rationale of one proposed security fix for the people who will "
    "approve it. The fix itself was produced by a deterministic rule and is already decided; "
    "you only describe it.\n\n"
    "The user message holds one <remediation> block with a JSON object. Its `facts` describe "
    "the gap and the change. Its `sources` are numbered S1, S2, ... and are the only outside "
    "material you may rely on.\n\n"
    "Rules:\n"
    "1. Use ONLY the facts and the sources. Do not invent hosts, controls, settings, or numbers.\n"
    "2. Do not describe any change other than the one in the facts.\n"
    "3. Cite a claim drawn from a source as [S1], [S2]. Cite only sources you were given.\n\n"
    "Return one JSON object with `title` (one line, an instruction, under 100 characters) and "
    "`rationale` (2 to 4 sentences: what the simulation showed, what the change does, and why "
    "that helps)."
)


def template_text(candidate: Candidate, citations: Sequence[RemediationCitation]) -> tuple[str, str]:
    """Return the rule's own title and rationale, citing the first source when there is one."""
    rationale = candidate.template_rationale
    if citations:
        first = citations[0]
        rationale += f" See {first.source_name} {first.section_id} [{first.id}]."
    return candidate.template_title, rationale


def build_request(candidate: Candidate, citations: Sequence[RemediationCitation], sources: Sequence[dict[str, str]]) -> str:
    """Render the user message for the model. It contains no patch."""
    title, rationale = template_text(candidate, citations)
    payload = {
        "facts": {
            "rule": candidate.rule.value,
            "control_or_asset": candidate.target.code,
            "technique_id": candidate.technique_id,
            "step_order": candidate.step_order,
            "effort": candidate.effort.value,
            "affected_assets": candidate.affected_assets,
            "caveats": candidate.caveats,
            "template_title": title,
            "template_rationale": rationale,
        },
        "sources": list(sources),
    }
    return (
        "<remediation>\n" + json.dumps(payload, indent=2, sort_keys=True) + "\n</remediation>\n\n"
        "Write the title and rationale for this fix."
    )


def text_problems(title: str, rationale: str, citations: Sequence[RemediationCitation]) -> list[str]:
    """Return what is wrong with model-written text. Empty means it may be used."""
    problems: list[str] = []
    if not title.strip() or "\n" in title.strip() or len(title) > MAX_TITLE:
        problems.append("title must be one non-empty line of at most 140 characters")
    if not rationale.strip() or len(rationale) > MAX_RATIONALE:
        problems.append("rationale must be non-empty and at most 1200 characters")
    known = {citation.id for citation in citations}
    for cited in cited_ids(f"{title} {rationale}"):
        if cited not in known:
            problems.append(f"[{cited}] is cited but was not provided")
    return problems


async def write_text(
    candidate: Candidate,
    citations: Sequence[RemediationCitation],
    sources: Sequence[dict[str, str]] = (),
    provider: Provider | None = None,
) -> tuple[str, str, str]:
    """Return (title, rationale, generated_by) for a candidate.

    Asks the model once. If the call fails, the output is not the expected JSON, or
    the text cites a source it was not given, the rule's template text is used and
    generated_by is "template".
    """
    backend = provider or get_provider()
    fallback_title, fallback_rationale = template_text(candidate, citations)
    result = await complete(
        SYSTEM_PROMPT,
        [LLMMessage(role="user", content=build_request(candidate, citations, sources))],
        json_schema=TEXT_SCHEMA,
        provider=backend,
    )
    data = result.data or {}
    title, rationale = data.get("title"), data.get("rationale")
    if result.ok and isinstance(title, str) and isinstance(rationale, str):
        problems = text_problems(title, rationale, citations)
        if not problems:
            return title.strip(), rationale.strip(), result.provider
        logger.warning("remediation text rejected", extra={"problems": problems})
    return fallback_title, fallback_rationale, TEMPLATE
