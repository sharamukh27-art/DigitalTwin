"""Deterministic explanation built from the context alone. No LLM involved.

Used as the fallback when the model's answers fail validation, and by the mock
provider. It only restates values from the findings and quotes the supplied sources.
"""

from typing import Any

NOT_COVERED = "not covered by the provided sources"
MAX_RECOMMENDATIONS = 4
_STANDARDS = ("d3fend", "nist")
_OUTCOME_TEXT = {
    "blocked": "was blocked",
    "detected_not_blocked": "was detected but not blocked",
    "undetected": "went undetected",
}


def _codes(items: list[dict[str, Any]]) -> str:
    return ", ".join(item["code"] for item in items)


def _mapped(technique_id: str, sources: list[dict[str, Any]], kinds: tuple[str, ...]) -> dict[str, Any] | None:
    """Return the first supplied source of the given kinds that is mapped to a technique."""
    return next(
        (
            source
            for source in sources
            if source.get("kind") in kinds and technique_id in source.get("technique_ids", [])
        ),
        None,
    )


def sources_for_recommendation(technique_id: str, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pick the sources a recommendation about a technique should cite.

    A D3FEND or NIST source mapped to the technique and a policy section that names it
    are both cited when present. Failing those, the technique's own ATT&CK entry, which
    lists its mitigations. As a last resort, any D3FEND or NIST source supplied.
    """
    chosen = [
        source
        for source in (_mapped(technique_id, sources, _STANDARDS), _mapped(technique_id, sources, ("policy",)))
        if source is not None
    ]
    if chosen:
        return chosen
    fallback = _mapped(technique_id, sources, ("attack",)) or next(
        (source for source in sources if source.get("kind") in _STANDARDS), None
    )
    return [fallback] if fallback is not None else []


def compose_explanation(context: dict[str, Any]) -> dict[str, Any]:
    """Build an explanation body from a context dict (see explain.build_context).

    Every number and code is copied from the findings. Every recommendation cites a
    supplied source; with no usable source, no recommendation is made.
    """
    findings: dict[str, Any] = context["findings"]
    risk: dict[str, Any] = context["risk"]
    sources: list[dict[str, Any]] = context.get("sources", [])
    killchain: list[dict[str, Any]] = findings["killchain"]
    depth = findings["attack_depth"]
    blast = findings["blast_radius"]
    used: list[str] = []

    def cite(chosen: list[dict[str, Any]]) -> list[str]:
        for source in chosen:
            if source["id"] not in used:
                used.append(source["id"])
        return [source["id"] for source in chosen]

    def marker(ids: list[str]) -> str:
        return "".join(f" [{item}]" for item in ids)

    if findings["first_detection_step"] is None:
        detection = "No control detected the attack at any step."
    else:
        detection = (
            f"It was first detected at step {findings['first_detection_step']}, "
            f"{findings['time_to_detect_seconds']} seconds after the start."
        )
    reached = ", ".join(blast["asset_codes"]) if blast["asset_codes"] else "no assets"
    summary = (
        f"Scenario {findings['scenario_code']} ended with containment {findings['containment']} "
        f"and a risk score of {risk['score']} ({risk['band']}). "
        f"The attack completed {depth['hops_achieved']} of {depth['total_steps']} steps and reached {reached}. "
        f"{detection}"
    )

    timeline = []
    for step in killchain:
        own_entry = _mapped(step["technique_id"], sources, ("attack",))
        ids = cite([own_entry] if own_entry is not None else [])
        target = f" against {step['target_code']}" if step.get("target_code") else ""
        timeline.append(
            {
                "step_order": step["step_order"],
                "plain_explanation": (
                    f"Step {step['step_order']}: {step['technique_id']} {step['technique_name']}"
                    f"{target} {_OUTCOME_TEXT[step['outcome']]}.{marker(ids)}"
                ),
                "citation_ids": ids,
            }
        )

    reasons: list[str] = []
    if findings["blocking_controls"]:
        reasons.append(f"Blocked by {_codes(findings['blocking_controls'])}.")
    if findings["detecting_controls"]:
        reasons.append(f"Detected by {_codes(findings['detecting_controls'])}.")
    for missed in findings["missed_controls"]:
        reasons.append(
            f"{missed['code']} missed {missed['technique_id']} at step {missed['step_order']}: {missed['reason']}."
        )
    for gap in findings["not_seen_gaps"]:
        reasons.append(f"Step {gap['step_order']} was a blind spot: {gap['note']}")
    if findings["weakest_link"] is not None:
        reasons.append(f"Weakest link: {findings['weakest_link']['explanation']}")
    if not reasons:
        reasons.append("No control reacted to the executed steps.")
    if not sources:
        reasons.append(f"Why these controls behave this way is {NOT_COVERED}.")

    techniques = {step["step_order"]: step["technique_id"] for step in killchain}
    control_codes = set(context.get("control_codes", []))
    wanted: list[tuple[str, str | None, str, str]] = []
    link = findings["weakest_link"]
    if link is not None and link["step_order"] in techniques:
        code = link["ref"] if link["ref"] in control_codes else None
        wanted.append((f"Fix the weakest link first. {link['explanation']}", code, techniques[link["step_order"]], "medium"))
    for missed in findings["missed_controls"]:
        wanted.append(
            (f"Correct {missed['code']} so that it handles {missed['technique_id']}: {missed['reason']}.",
             missed["code"], missed["technique_id"], "low")
        )
    for gap in findings["not_seen_gaps"]:
        wanted.append(
            (f"Add a control that can see {gap['technique_id']} at step {gap['step_order']}; none was applicable.",
             None, gap["technique_id"], "high")
        )

    recommendations = []
    seen: set[tuple[str | None, str]] = set()
    for text, code, technique_id, effort in wanted:
        if (code, technique_id) in seen or len(recommendations) >= MAX_RECOMMENDATIONS:
            continue
        chosen = sources_for_recommendation(technique_id, sources)
        if not chosen:
            continue
        seen.add((code, technique_id))
        ids = cite(chosen)
        references = " and ".join(f"{source['source_name']} {source['section_id']}" for source in chosen)
        recommendations.append(
            {
                "text": f"{text} See {references}.{marker(ids)}",
                "related_control_code": code,
                "related_technique_id": technique_id,
                "citation_ids": ids,
                "effort_hint": effort,
            }
        )

    by_id = {source["id"]: source for source in sources}
    return {
        "summary": summary,
        "timeline": timeline,
        "why_caught_or_missed": " ".join(reasons),
        "recommendations": recommendations,
        "citations": [
            {"id": item, "source_name": by_id[item]["source_name"], "source_url": by_id[item]["source_url"]}
            for item in sorted(used, key=lambda value: int(value[1:]))
        ],
    }
