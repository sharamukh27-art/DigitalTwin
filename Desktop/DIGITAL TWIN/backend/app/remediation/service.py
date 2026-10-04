"""Generate remediations for a run: rules give the patch, retrieval the citations, the LLM the text."""

import asyncio
import logging

from app.analysis import service as analysis_service
from app.models.enums import RemediationStatus, SourceKind
from app.models.remediation import SYSTEM_ACTOR, Candidate, Remediation, RemediationCitation
from app.rag.retrieve import retrieve
from app.remediation import audit, repository, rules, text
from app.simulation import repository as run_repository
from app.twin import techniques

logger = logging.getLogger(__name__)

CITATIONS_PER_FIX = 3
RETRIEVE_K = 6
_STANDARDS = (SourceKind.D3FEND, SourceKind.NIST)
_KIND_ORDER = [SourceKind.ATTACK, SourceKind.POLICY, SourceKind.D3FEND, SourceKind.NIST, SourceKind.CIS]
_REUSABLE = (RemediationStatus.PROPOSED, RemediationStatus.VERIFIED)


def _cite(candidate: Candidate) -> tuple[list[RemediationCitation], list[dict[str, str]]]:
    """Retrieve sources for a candidate. Returns (citations, sources with text for the model).

    Keeps sources mapped to the fix's technique first (its ATT&CK entry, then policy
    sections, then mapped defenses), then other D3FEND or NIST entries. Entries for
    other ATT&CK techniques are dropped.
    """
    technique = techniques.get(candidate.technique_id)
    query = f"{candidate.template_title}. {technique.name} mitigation hardening"
    retrieved = retrieve(query, [candidate.technique_id], RETRIEVE_K)
    mapped = sorted(
        (chunk for chunk in retrieved if candidate.technique_id in chunk.technique_ids),
        key=lambda chunk: _KIND_ORDER.index(chunk.kind),
    )
    standards = [chunk for chunk in retrieved if chunk not in mapped and chunk.kind in _STANDARDS]
    chunks = (mapped + standards)[:CITATIONS_PER_FIX]
    citations = [
        RemediationCitation(
            id=f"S{index}", source_name=chunk.source_name, source_url=chunk.source_url, section_id=chunk.section_id
        )
        for index, chunk in enumerate(chunks, start=1)
    ]
    sources = [
        {"id": citation.id, "source_name": citation.source_name, "section_id": citation.section_id, "text": chunk.text}
        for citation, chunk in zip(citations, chunks)
    ]
    return citations, sources


async def _build(candidate: Candidate, run_id: str, network_id: str, scenario_code: str) -> Remediation:
    citations, sources = await asyncio.to_thread(_cite, candidate)
    title, rationale, generated_by = await text.write_text(candidate, citations, sources)
    return Remediation(
        network_id=network_id,
        run_id=run_id,
        scenario_code=scenario_code,
        technique_id=candidate.technique_id,
        rule=candidate.rule,
        title=title,
        rationale=rationale,
        text_generated_by=generated_by,
        target=candidate.target,
        affected_assets=candidate.affected_assets,
        patch=candidate.patch,
        fingerprint=rules.fingerprint(candidate.patch),
        config_snippet=candidate.config_snippet,
        citations=citations,
        effort=candidate.effort,
        notes=[f"caveat: {caveat}" for caveat in candidate.caveats],
    )


async def generate_for_run(run_id: str) -> list[Remediation]:
    """Generate and store the candidate remediations of a run. Returns them in step order.

    A candidate whose patch equals an existing proposed or verified remediation of the
    same network is not stored again; the existing one is returned in its place.
    Raises NotFound for an unknown run and ValidationFailed for a run that did not complete.
    """
    run = await run_repository.get_run(run_id)
    findings = await analysis_service.findings_for(run)
    twin = await analysis_service.load_twin(run.network_id)

    results: list[Remediation] = []
    for candidate in rules.generate_candidates(run, findings, twin):
        existing = await repository.find_open_by_fingerprint(
            run.network_id, rules.fingerprint(candidate.patch), _REUSABLE
        )
        if existing is not None:
            results.append(existing)
            continue
        created = await repository.insert_remediation(
            await _build(candidate, run.id, run.network_id, run.scenario_code)
        )
        await audit.record_change(
            SYSTEM_ACTOR, "remediation.proposed", None, created, f"rule {created.rule.value} on run {run.id}"
        )
        results.append(created)
    logger.info("remediations generated", extra={"run_id": run.id, "count": len(results)})
    return results
