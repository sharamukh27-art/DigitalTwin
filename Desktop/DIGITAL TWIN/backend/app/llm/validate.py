"""Checks that an explanation does not contradict the findings or cite sources it was not given."""

import re
from collections.abc import Iterable
from typing import Any

from app.models.explanation import ExplanationBody

CITATION_PATTERN = re.compile(r"\[(S\d+)\]")
_STATED_SCORE = (
    re.compile(r"risk\s+score\D{0,25}?(\d{1,3})\b", flags=re.IGNORECASE),
    re.compile(r"\b(\d{1,3})\s*/\s*100\b"),
    re.compile(r"\b(\d{1,3})\s+out\s+of\s+100\b", flags=re.IGNORECASE),
)
_CONTAINMENT_PHRASES = ("partially contained", "objective reached")


def cited_ids(text: str) -> list[str]:
    """Return the source ids cited in a text as [S1], [S2], ..., in order, without repeats."""
    seen: list[str] = []
    for match in CITATION_PATTERN.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def containment_words(text: str) -> set[str]:
    """Return which containment values a text states.

    Matches the values with underscores or spaces, in any case. "contained" is only
    counted where it is not part of "partially contained".
    """
    normalised = text.lower().replace("_", " ")
    found: set[str] = set()
    for phrase in _CONTAINMENT_PHRASES:
        if phrase in normalised:
            found.add(phrase.replace(" ", "_"))
            normalised = normalised.replace(phrase, " ")
    if re.search(r"\bcontained\b", normalised):
        found.add("contained")
    return found


def stated_scores(text: str) -> list[int]:
    """Return every number a text presents as the risk score."""
    return [int(match) for pattern in _STATED_SCORE for match in pattern.findall(text)]


def _all_texts(body: ExplanationBody) -> Iterable[str]:
    yield body.summary
    yield body.why_caught_or_missed
    for item in body.timeline:
        yield item.plain_explanation
    for recommendation in body.recommendations:
        yield recommendation.text


def validate_explanation(body: ExplanationBody, context: dict[str, Any]) -> list[str]:
    """Return every problem with an explanation. An empty list means it may be shown.

    Checks, against the context that was given to the model:
    - the summary states the right containment value and no other
    - the summary contains the risk score, and no text states a different one
    - every recommendation has at least one citation
    - every [Sn] used, in text or in citation_ids, is listed in `citations`
    - every listed citation is a supplied source with the same name and url
    - recommendations name only controls of this network and techniques of this run
    - timeline entries refer only to executed steps
    """
    findings: dict[str, Any] = context["findings"]
    score = int(context["risk"]["score"])
    containment = str(findings["containment"])
    sources = {source["id"]: source for source in context.get("sources", [])}
    errors: list[str] = []

    stated = containment_words(body.summary)
    if containment not in stated:
        errors.append(f"summary must state the containment value exactly: {containment}")
    for other in sorted(stated - {containment}):
        errors.append(f"summary says '{other}' but the findings say containment is {containment}")

    if not re.search(rf"(?<![\d.]){score}(?![\d.])", body.summary):
        errors.append(f"summary must contain the risk score {score}")
    for text in _all_texts(body):
        for wrong in sorted({value for value in stated_scores(text) if value != score}):
            errors.append(f"text states a risk score of {wrong} but the findings say {score}")

    listed = {citation.id for citation in body.citations}
    used: list[str] = []
    for text in _all_texts(body):
        used.extend(cited_ids(text))
    for item in body.timeline:
        used.extend(item.citation_ids)
    for index, recommendation in enumerate(body.recommendations, start=1):
        if not recommendation.citation_ids:
            errors.append(f"recommendation {index} has no citation")
        used.extend(recommendation.citation_ids)
    for missing in sorted(set(used) - listed, key=lambda value: (len(value), value)):
        errors.append(f"[{missing}] is cited but is not in the citations list")

    for citation in body.citations:
        source = sources.get(citation.id)
        if source is None:
            errors.append(f"citation {citation.id} is not one of the provided sources")
        elif (citation.source_name, citation.source_url) != (source["source_name"], source["source_url"]):
            errors.append(f"citation {citation.id} does not match the name and url of source {citation.id}")

    techniques = {step["technique_id"] for step in findings["killchain"]}
    steps = {step["step_order"] for step in findings["killchain"]}
    controls = set(context.get("control_codes", []))
    for index, recommendation in enumerate(body.recommendations, start=1):
        code = recommendation.related_control_code
        if code is not None and code not in controls:
            errors.append(f"recommendation {index} names control {code}, which is not in this network")
        if recommendation.related_technique_id not in techniques:
            errors.append(
                f"recommendation {index} names technique {recommendation.related_technique_id}, "
                "which is not in this run"
            )
    for item in body.timeline:
        if item.step_order not in steps:
            errors.append(f"timeline has step {item.step_order}, which was not executed")
    return errors
