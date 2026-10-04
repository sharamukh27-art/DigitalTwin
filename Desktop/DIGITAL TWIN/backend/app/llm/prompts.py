"""Prompt text for grounded explanations, and the context block format."""

import json
import re
from typing import Any

RULES: tuple[str, ...] = (
    "Use ONLY facts in the FINDINGS JSON or the SOURCES. Do not invent hosts, controls, or numbers.",
    "Never alter detection, containment, risk score, or counts. Quote them exactly as given.",
    "Cite every claim drawn from a source as [S1], [S2]. Recommendations must each cite at least one source.",
    'If the sources do not cover a point, write "not covered by the provided sources".',
)

SYSTEM_PROMPT = (
    "You explain the result of a simulated cyber attack to the people who defend the network. "
    "The simulation ran on a digital twin of the network, not on real systems. A deterministic "
    "engine already decided what was detected, blocked and missed, and computed the risk score. "
    "Your job is to explain those results in plain language and to recommend fixes that are "
    "grounded in the supplied sources. You never compute or change any value.\n\n"
    "Rules:\n"
    + "\n".join(f"{index}. {rule}" for index, rule in enumerate(RULES, start=1))
    + "\n\n"
    "The user message holds one <context> block with a JSON object. Its `findings` and `risk` "
    "keys are the FINDINGS JSON. Its `sources` key is the SOURCES: a numbered list where each "
    "entry has an id (S1, S2, ...), a name, a url and the text you may rely on.\n\n"
    "Return one JSON object with these keys:\n"
    "- summary: 3 to 4 sentences. It must contain the containment value exactly as given in "
    "findings.containment (for example objective_reached) and the risk score integer exactly as "
    "given in risk.score.\n"
    "- timeline: one entry per step in findings.killchain, in order, with step_order, a "
    "plain_explanation of what happened at that step, and citation_ids for any source you relied on.\n"
    "- why_caught_or_missed: a short paragraph on which controls detected or blocked the attack, "
    "which missed it and why, using the reasons given in the findings.\n"
    "- recommendations: the most useful fixes first. Each has text, related_control_code (a "
    "control code that appears in the findings, or null), related_technique_id (a technique id "
    "from findings.killchain), citation_ids with at least one source id, and effort_hint "
    "(low, medium or high).\n"
    "- citations: one entry for every source id you used, with the id, source_name and "
    "source_url copied exactly from the SOURCES.\n\n"
    "Write for a reader who is technical but was not present for the simulation. Use the asset "
    "and control codes from the findings as they are written."
)

_CONTEXT_BLOCK = re.compile(r"<context>\s*(\{.*\})\s*</context>", flags=re.DOTALL)


def render_context(context: dict[str, Any]) -> str:
    """Render the user message that carries the context block."""
    return (
        "<context>\n"
        + json.dumps(context, indent=2, sort_keys=True)
        + "\n</context>\n\nExplain this simulation run. Return the JSON object described in your instructions."
    )


def extract_context(message: str) -> dict[str, Any] | None:
    """Return the JSON object inside a message's <context> block, or None."""
    match = _CONTEXT_BLOCK.search(message)
    if match is None:
        return None
    try:
        parsed = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


_REMEDIATION_BLOCK = re.compile(r"<remediation>\s*(\{.*\})\s*</remediation>", flags=re.DOTALL)


def extract_remediation(message: str) -> dict[str, Any] | None:
    """Return the JSON object inside a message's <remediation> block, or None."""
    match = _REMEDIATION_BLOCK.search(message)
    if match is None:
        return None
    try:
        parsed = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def render_retry(errors: list[str]) -> str:
    """Render the follow-up message sent when the first answer failed validation."""
    return (
        "Your previous answer was rejected by an automatic check against the findings. "
        "Problems found:\n"
        + "\n".join(f"- {error}" for error in errors)
        + "\n\nReturn the full JSON object again with these problems fixed. Keep to the rules: "
        "quote the containment value and the risk score exactly as given, and cite a source for "
        "every recommendation."
    )
