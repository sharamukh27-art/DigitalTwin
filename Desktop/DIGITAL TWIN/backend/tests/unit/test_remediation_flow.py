"""Remediation text, generation, verification, bundles, approval, audit and export."""

import json
from typing import Any

import pytest

from app.analysis import posture as posture_module
from app.controls import repository as control_repository
from app.core import db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.llm.client import ProviderError
from app.llm.providers import MockProvider
from app.models.enums import FinalOutcome, RemediationStatus
from app.models.remediation import Remediation, RemediationCitation, RemediationUpdate
from app.models.whatif import PatchOp, WhatIfDiff
from app.rag.documents import IngestSummary
from app.remediation import approval, audit, repository, rules, service, text, verify
from app.remediation.export import render_change_plan
from app.remediation.ranking import priority, rank
from app.simulation import engine
from app.simulation import repository as run_repository
from app.twin import repository as twin_repository

DAI = "Enable dynamic ARP inspection on SWSEC-2"
NAC = "Disable MAC authentication bypass on NAC-01"
LOCKOUT = "Set an account lockout threshold on IDP-01"
NO_GAIN = "Extend IDS-01 to the corporate zone"
DENY_DB = "Deny server to server on port 5432 at FW-INT"


async def generate(network_id: str, scenario: str) -> dict[str, Remediation]:
    run = await engine.run(network_id, scenario)
    return {item.title: item for item in await service.generate_for_run(run.id)}


async def count(collection: str, **query: Any) -> int:
    return await db.collection(collection).count_documents(query)


async def actions(network_id: str) -> list[str]:
    entries, _ = await repository.list_audit(network_id, 500, 0)
    return [entry.action for entry in entries]


def diff(code: str, before: int, after: int, was: str = "objective_reached", now: str = "objective_reached") -> WhatIfDiff:
    return WhatIfDiff(
        scenario_code=code, risk_before=before, risk_after=after, delta=after - before,
        containment_before=was, containment_after=now, steps_changed=[],
    )


# --- text -------------------------------------------------------------------


async def candidate_and_citations(acme_id: str) -> tuple[Any, list[RemediationCitation]]:
    from app.analysis import service as analysis_service

    run = await engine.run(acme_id, "S1")
    twin = await analysis_service.load_twin(acme_id)
    candidate = rules.generate_candidates(run, await analysis_service.findings_for(run), twin)[0]
    citations = [RemediationCitation(id="S1", source_name="MITRE ATT&CK", source_url="u", section_id="T1557.002")]
    return candidate, citations


async def test_text_from_the_model_is_used_when_valid(acme_id: str) -> None:
    candidate, citations = await candidate_and_citations(acme_id)
    answer = {"title": "Turn on ARP inspection for floor 2", "rationale": "The switch let ARP poisoning through [S1]. Inspection drops forged replies."}
    provider = MockProvider(script=[json.dumps(answer)])
    assert await text.write_text(candidate, citations, provider=provider) == (answer["title"], answer["rationale"], "mock")

    request = provider.calls[0][0].content
    assert request.startswith("<remediation>\n{")
    assert '"patch"' not in request and '"set"' not in request and "config." not in request
    assert '"technique_id": "T1557.002"' in request


async def test_text_falls_back_to_the_template(acme_id: str) -> None:
    candidate, citations = await candidate_and_citations(acme_id)
    template = (
        DAI,
        "In scenario S1 step 1, T1557.002 ARP Cache Poisoning against SW-ACCESS-2 was missed by SWSEC-2: "
        "dynamic_arp_inspection is false on SWSEC-2. With this change SWSEC-2 can block it. "
        "See MITRE ATT&CK T1557.002 [S1].",
        "template",
    )
    for bad in (
        json.dumps({"title": "Fix it", "rationale": "As shown in the vendor guide [S7]."}),
        json.dumps({"title": "", "rationale": "No title."}),
        json.dumps({"title": "Two\nlines", "rationale": "x"}),
        json.dumps({"title": "T" * 200, "rationale": "x"}),
        json.dumps({"title": "Only a title"}),
        "not json",
        ProviderError("auth", "bad key"),
    ):
        assert await text.write_text(candidate, citations, provider=MockProvider(script=[bad])) == template

    assert await text.write_text(candidate, citations) == (template[0], template[1], "mock")
    assert text.template_text(candidate, [])[1].endswith("With this change SWSEC-2 can block it.")
    assert text.text_problems("Fine", "Cites [S1] only.", citations) == []


# --- generation -------------------------------------------------------------


async def test_generation_stores_candidates_and_is_idempotent(acme_id: str, kb_index: IngestSummary) -> None:
    run = await engine.run(acme_id, "S1")
    first = await service.generate_for_run(run.id)
    assert len(first) == 9
    assert await count(db.REMEDIATIONS) == 9
    assert (await actions(acme_id)).count("remediation.proposed") == 9

    dai = next(item for item in first if item.title == DAI)
    assert (dai.status, dai.network_id, dai.run_id, dai.scenario_code) == (RemediationStatus.PROPOSED, acme_id, run.id, "S1")
    assert (dai.rule.value, dai.effort.value, dai.target.code, dai.text_generated_by) == ("missed_requirement", "low", "SWSEC-2", "mock")
    assert dai.patch == [PatchOp(target="control", code="SWSEC-2", set={"config.dynamic_arp_inspection": True})]
    assert dai.fingerprint == rules.fingerprint(dai.patch)
    assert dai.config_snippet == "ip arp inspection vlan 10,50"
    assert (dai.verification, dai.risk_reduction, dai.approved_by, dai.approved_at) == (None, None, None, None)
    assert [c.section_id for c in dai.citations] == [
        "T1557.002", "network_access_policy#layer-2-protection-on-access-switches", "D3-NTA",
    ]
    assert [c.id for c in dai.citations] == ["S1", "S2", "S3"]
    assert dai.rationale.endswith("See MITRE ATT&CK T1557.002 [S1].")
    hole = next(item for item in first if item.title == DENY_DB)
    assert hole.notes == ["caveat: The twin models attack paths, not business traffic. Confirm that no legitimate flow needs this before applying."]

    again = await service.generate_for_run(run.id)
    assert [item.id for item in again] == [item.id for item in first]
    assert await count(db.REMEDIATIONS) == 9

    other = await generate(acme_id, "S3")
    assert other[DENY_DB].id == hole.id and other[DENY_DB].scenario_code == "S1"
    assert other["Switch WAF-01 from detect to block mode"].scenario_code == "S3"


async def test_the_model_cannot_change_the_patch(acme_id: str, offline_ai: MockProvider) -> None:
    lie = {"title": "Disable the switch", "rationale": "Trust me.", "patch": [{"code": "SWSEC-2", "set": {"enabled": False}}]}
    offline_ai.script = [json.dumps(lie)]
    found = await generate(acme_id, "S1")
    stored = found["Disable the switch"]
    assert stored.patch == [PatchOp(target="control", code="SWSEC-2", set={"config.dynamic_arp_inspection": True})]
    assert stored.config_snippet == "ip arp inspection vlan 10,50"


async def test_generation_errors(acme_id: str) -> None:
    with pytest.raises(NotFound):
        await service.generate_for_run("missing")
    assert await generate(acme_id, "S2") == {}


# --- verification -----------------------------------------------------------


def test_judge() -> None:
    assert verify.judge([diff("S1", 39, 0, now="contained"), diff("S2", 0, 0, "contained", "contained")], ["S1"]) == (
        True, ["improved: S1 risk 39 -> 0, objective_reached -> contained"],
    )
    same_risk = diff("S1", 40, 40, "objective_reached", "partially_contained")
    assert verify.judge([same_risk], ["S1"])[0] is True

    assert verify.judge([diff("S1", 39, 39)], ["S1"]) == (
        False, ["no improvement: S1 risk stayed at 39 and containment stayed objective_reached"],
    )
    assert verify.judge([diff("S1", 39, 0, now="contained"), diff("S4", 46, 50)], ["S1"]) == (
        False, ["regression: S4 risk rose from 46 to 50"],
    )
    newly = diff("S2", 0, 34, "contained", "objective_reached")
    assert verify.judge([diff("S1", 39, 0, now="contained"), newly], ["S1"]) == (
        False, ["regression: S2 risk rose from 0 to 34", "regression: S2 now reaches its objective"],
    )
    assert verify.judge([diff("S1", 39, 45)], ["S1"])[1] == [
        "regression: S1 risk rose from 39 to 45",
        "no improvement: S1 risk stayed at 45 and containment stayed objective_reached",
    ]
    assert verify.judge([diff("S1", 39, 39), diff("S3", 51, 0, now="contained")], ["S1"])[0] is False
    assert verify.judge([diff("S1", 39, 39), diff("S3", 51, 0, now="contained")], ["S1", "S3"])[0] is True


async def test_verified_fix_lowers_its_scenario_and_worsens_nothing(acme_id: str) -> None:
    found = await generate(acme_id, "S1")
    result = await verify.verify(found[DAI].id)

    assert (result.status, result.verified_network_version) == (RemediationStatus.VERIFIED, 1)
    assert (result.risk_reduction, result.priority) == (6.5, 6.5)
    check = result.verification
    assert check is not None and check.verified is True
    assert (check.network_version, check.seed) == (1, 42)
    assert check.reasons == ["improved: S1 risk 39 -> 0, objective_reached -> contained"]
    assert [(i.scenario_code, i.risk_score) for i in check.before.per_scenario] == [
        ("S1", 39), ("S2", 0), ("S3", 51), ("S4", 46), ("S5", 52), ("S6", 56),
    ]
    assert [(i.scenario_code, i.risk_score, i.containment.value) for i in check.after.per_scenario][0] == ("S1", 0, "contained")
    assert (check.before.average_risk, check.after.average_risk) == (40.67, 34.17)
    assert (check.before.posture_score, check.after.posture_score) == (57, 63)
    assert all(item.delta <= 0 for item in check.diff)
    assert [item.delta for item in check.diff] == [-39, 0, 0, 0, 0, 0]
    assert result.notes == ["verified on network version 1: improved: S1 risk 39 -> 0, objective_reached -> contained"]
    assert await repository.get_remediation(result.id) == result
    assert (await actions(acme_id))[-1] == "remediation.verified"

    assert await count(db.NETWORKS) == 1
    assert (await twin_repository.get_network(acme_id)).version == 1
    swsec = next(c for c in await control_repository.all_controls(acme_id) if c.code == "SWSEC-2")
    assert swsec.config.dynamic_arp_inspection is False
    assert await count(db.SIMULATION_RUNS) == 1


async def test_fix_without_effect_is_not_verified_and_says_why(acme_id: str) -> None:
    found = await generate(acme_id, "S1")
    result = await verify.verify(found[NO_GAIN].id)
    assert (result.status, result.priority, result.verified_network_version) == (RemediationStatus.PROPOSED, None, None)
    assert result.risk_reduction == 0.0
    assert result.verification is not None and result.verification.verified is False
    assert result.notes == [
        "not verified on network version 1: no improvement: S1 risk stayed at 39 and containment stayed objective_reached"
    ]
    assert (await actions(acme_id))[-1] == "remediation.verification_failed"


async def bad_remediation(acme_id: str, patch: list[PatchOp]) -> Remediation:
    found = await generate(acme_id, "S1")
    base = found[DAI]
    return await repository.insert_remediation(
        base.model_copy(update={"id": "bad-fix", "title": "Bad fix", "patch": patch, "fingerprint": rules.fingerprint(patch)})
    )


async def test_patch_that_breaks_another_scenario_is_not_verified(acme_id: str) -> None:
    bad = await bad_remediation(
        acme_id,
        [
            PatchOp(target="control", code="SWSEC-2", set={"config.dynamic_arp_inspection": True}),
            PatchOp(target="control", code="MAIL-01", set={"config.attachment_sandboxing": False}),
        ],
    )
    result = await verify.verify(bad.id)

    assert result.status == RemediationStatus.PROPOSED
    assert (result.priority, result.verified_network_version) == (None, None)
    check = result.verification
    assert check is not None and check.verified is False
    s1, s2 = check.diff[0], check.diff[1]
    assert (s1.risk_after, s1.containment_after) == (0, FinalOutcome.CONTAINED)
    assert s2.risk_before == 0 and s2.risk_after > 0
    assert check.reasons == [
        f"regression: S2 risk rose from 0 to {s2.risk_after}",
        "regression: S2 now reaches its objective",
    ]
    assert result.notes[-1].startswith("not verified on network version 1: regression: S2 risk rose from 0 to")

    with pytest.raises(Conflict, match="Only a verified remediation can be approved"):
        await approval.decide(bad.id, RemediationUpdate(status="approved", actor="alice"))
    assert (await twin_repository.get_network(acme_id)).version == 1


async def test_patch_that_cannot_be_applied_is_not_verified(acme_id: str) -> None:
    bad = await bad_remediation(acme_id, [PatchOp(target="control", code="GONE-01", set={"enabled": False})])
    result = await verify.verify(bad.id)
    assert (result.status, result.verification, result.risk_reduction) == (RemediationStatus.PROPOSED, None, None)
    assert result.notes[-1] == (
        "not verified on network version 1: patch could not be applied "
        "(patch[0] (control GONE-01): no control with code GONE-01)"
    )
    assert await count(db.NETWORKS) == 1
    with pytest.raises(NotFound):
        await verify.verify("missing")


def test_ranking() -> None:
    assert (priority(6.0, "low"), priority(6.0, "medium"), priority(6.0, "high")) == (6.0, 3.0, 2.0)


async def test_rank_orders_verified_fixes_by_reduction_per_effort(acme_id: str) -> None:
    found = {**await generate(acme_id, "S1"), **await generate(acme_id, "S4")}
    for title in (NAC, DAI, LOCKOUT, DENY_DB, NO_GAIN):
        await verify.verify(found[title].id)
    ranked = rank(await repository.list_remediations(acme_id))
    assert [(item.title, item.priority) for item in ranked[:4]] == [
        (DAI, 6.5), (LOCKOUT, 5.34), (NAC, 2.67), (DENY_DB, 2.0),
    ]
    assert all(item.status == RemediationStatus.PROPOSED for item in ranked[4:])
    assert len(ranked) == 12


async def test_bundle_reports_the_combined_reduction(acme_id: str) -> None:
    found = {**await generate(acme_id, "S1"), **await generate(acme_id, "S4")}
    dai = await verify.verify(found[DAI].id)
    lockout = await verify.verify(found[LOCKOUT].id)

    bundle = await verify.verify_bundle([dai.id, lockout.id])
    assert bundle.remediation_ids == [dai.id, lockout.id]
    assert bundle.patch == [*dai.patch, *lockout.patch]
    assert bundle.individual_risk_reductions == {dai.id: 6.5, lockout.id: 5.34}
    assert bundle.risk_reduction == 11.84
    assert bundle.risk_reduction > max(dai.risk_reduction, lockout.risk_reduction)
    assert bundle.verification.verified is True
    assert bundle.verification.reasons == [
        "improved: S1 risk 39 -> 0, objective_reached -> contained",
        "improved: S4 risk 46 -> 14, objective_reached -> partially_contained",
    ]
    assert {d.scenario_code: d.delta for d in bundle.verification.diff} == {"S1": -39, "S2": 0, "S3": 0, "S4": -32, "S5": 0, "S6": 0}
    assert (await repository.get_remediation(dai.id)) == dai
    assert await count(db.NETWORKS) == 1

    overlapping = await verify.verify_bundle([dai.id, found[NAC].id])
    assert overlapping.risk_reduction == 6.5


async def test_bundle_errors(acme_id: str) -> None:
    found = await generate(acme_id, "S1")
    dai, nac = found[DAI].id, found[NAC].id
    with pytest.raises(ValidationFailed, match="same remediation twice"):
        await verify.verify_bundle([dai, dai])
    with pytest.raises(NotFound):
        await verify.verify_bundle([dai, "missing"])
    await approval.decide(nac, RemediationUpdate(status="rejected", actor="bob", note="no"))
    with pytest.raises(Conflict, match="cannot be bundled"):
        await verify.verify_bundle([dai, nac])


# --- approval and audit -----------------------------------------------------


async def test_approving_applies_to_the_twin_and_writes_audit_entries(acme_id: str) -> None:
    found = await generate(acme_id, "S1")
    verified = await verify.verify(found[DAI].id)
    before = await posture_module.posture(acme_id)
    twin_before = await audit.twin_hash(acme_id)

    applied = await approval.decide(verified.id, RemediationUpdate(status="approved", actor="alice", note="change window 12"))

    assert applied.status == RemediationStatus.APPLIED
    assert applied.approved_by == "alice" and applied.approved_at is not None
    assert applied.notes[-2:] == ["approved by alice: change window 12", "applied to the twin as network version 2"]
    assert (await repository.get_remediation(applied.id)).status == RemediationStatus.APPLIED

    network = await twin_repository.get_network(acme_id)
    assert network.version == 2
    swsec = next(c for c in await control_repository.all_controls(acme_id) if c.code == "SWSEC-2")
    assert swsec.config.dynamic_arp_inspection is True

    for scenario_code in ("S1", "S2", "S3", "S4", "S5", "S6"):
        from app.scenarios import catalog

        latest = await run_repository.latest_run(acme_id, catalog.get(scenario_code).id, 2)
        assert latest is not None and latest.seed == 42
    after = await posture_module.posture(acme_id, refresh=False)
    assert after.stale_scenarios == []
    assert (before.posture_score, after.posture_score) == (57, 63)
    assert next(i for i in after.per_scenario if i.scenario_code == "S1").containment == FinalOutcome.CONTAINED

    entries, total = await repository.list_audit(acme_id, 100, 0)
    assert [entry.action for entry in entries][-3:] == ["remediation.verified", "remediation.approved", "remediation.applied"]
    approved_entry, applied_entry = entries[-2], entries[-1]
    assert (approved_entry.actor, approved_entry.target, approved_entry.note) == ("alice", f"remediation:{applied.id}", "change window 12")
    assert approved_entry.before_hash == audit.remediation_hash(verified) != approved_entry.after_hash
    assert (applied_entry.actor, applied_entry.target) == ("alice", f"network:{acme_id}")
    assert applied_entry.before_hash == twin_before
    assert applied_entry.after_hash == await audit.twin_hash(acme_id) != twin_before
    assert all(len(h) == 64 for h in (applied_entry.before_hash, applied_entry.after_hash))
    assert "network version 1 -> 2" in applied_entry.note
    assert entries[0].before_hash == "-" and entries[0].actor == "system"
    assert [entry.at for entry in entries] == sorted(entry.at for entry in entries)
    assert total == len(entries) == 12


async def test_only_fresh_verified_fixes_can_be_approved(acme_id: str) -> None:
    found = {**await generate(acme_id, "S1"), **await generate(acme_id, "S4")}
    approve = RemediationUpdate(status="approved", actor="alice")

    with pytest.raises(Conflict, match="this one is proposed"):
        await approval.decide(found[DAI].id, approve)

    await verify.verify(found[DAI].id)
    await verify.verify(found[LOCKOUT].id)
    await approval.decide(found[DAI].id, approve)

    with pytest.raises(Conflict, match="verified on network version 1 but the network is now at version 2"):
        await approval.decide(found[LOCKOUT].id, approve)
    assert (await twin_repository.get_network(acme_id)).version == 2

    again = await verify.verify(found[LOCKOUT].id)
    assert (again.status, again.verified_network_version) == (RemediationStatus.VERIFIED, 2)
    done = await approval.decide(found[LOCKOUT].id, approve)
    assert done.status == RemediationStatus.APPLIED
    assert (await twin_repository.get_network(acme_id)).version == 3

    for decision in ("approved", "rejected"):
        with pytest.raises(Conflict):
            await approval.decide(found[DAI].id, RemediationUpdate(status=decision, actor="alice"))
    with pytest.raises(Conflict, match="cannot be verified"):
        await verify.verify(found[DAI].id)

    stale = await verify.verify(found[NAC].id)
    assert stale.status == RemediationStatus.PROPOSED
    assert "no improvement: S1 risk stayed at 0 and containment stayed contained" in stale.notes[-1]


async def test_rejecting_records_the_note_and_an_audit_entry(acme_id: str) -> None:
    found = await generate(acme_id, "S1")
    verified = await verify.verify(found[NAC].id)

    rejected = await approval.decide(verified.id, RemediationUpdate(status="rejected", actor="bob", note="printers need MAB"))
    assert rejected.status == RemediationStatus.REJECTED
    assert rejected.notes[-1] == "rejected by bob: printers need MAB"
    assert (rejected.approved_by, rejected.approved_at) == (None, None)
    assert (await twin_repository.get_network(acme_id)).version == 1

    entries, _ = await repository.list_audit(acme_id, 100, 0)
    last = entries[-1]
    assert (last.action, last.actor, last.note, last.target) == ("remediation.rejected", "bob", "printers need MAB", f"remediation:{rejected.id}")
    assert last.before_hash == audit.remediation_hash(verified) and last.after_hash == audit.remediation_hash(rejected)

    with pytest.raises(Conflict, match="is rejected and cannot be rejected"):
        await approval.decide(verified.id, RemediationUpdate(status="rejected", actor="bob"))
    with pytest.raises(NotFound):
        await approval.decide("missing", RemediationUpdate(status="rejected", actor="bob"))

    regenerated = await generate(acme_id, "S1")
    assert regenerated[NAC].id != rejected.id and regenerated[NAC].status == RemediationStatus.PROPOSED
    assert regenerated[DAI].id == found[DAI].id


async def test_deleting_a_network_removes_its_remediations_and_audit_log(acme_id: str) -> None:
    await generate(acme_id, "S1")
    assert await count(db.REMEDIATIONS) == 9 and await count(db.AUDIT_LOG) == 9
    await twin_repository.delete_network(acme_id)
    assert await count(db.REMEDIATIONS) == 0 and await count(db.AUDIT_LOG) == 0


# --- export -----------------------------------------------------------------


async def test_export_renders_every_verified_fix_with_snippet_and_citations(acme_id: str, kb_index: IngestSummary) -> None:
    found = {**await generate(acme_id, "S1"), **await generate(acme_id, "S4")}
    network = await twin_repository.get_network(acme_id)
    empty = render_change_plan(network, await repository.list_remediations(acme_id))
    assert "Fixes in this plan: 0" in empty and "No verified fixes yet." in empty

    for title in (DAI, LOCKOUT, DENY_DB, NO_GAIN):
        await verify.verify(found[title].id)
    await approval.decide(found[NAC].id, RemediationUpdate(status="rejected", actor="bob"))

    plan = render_change_plan(network, await repository.list_remediations(acme_id))
    assert plan.startswith("# Change plan: ACME Corp\n")
    assert "digital twin at network version 1" in plan
    assert "Nothing in this plan has been sent to a real device." in plan
    assert "Fixes in this plan: 3" in plan
    headings = [line for line in plan.splitlines() if line.startswith("## ")]
    assert headings == [f"## 1. {DAI}", f"## 2. {LOCKOUT}", f"## 3. {DENY_DB}"]
    assert NO_GAIN not in plan and NAC not in plan

    first = plan.split("## 2.")[0]
    for expected in (
        "- Status: verified, awaiting approval",
        "- Control: SWSEC-2",
        "- Affected devices: SW-ACCESS-2",
        "- Found by: scenario S1, technique T1557.002",
        "- Effort: low",
        "- Expected risk reduction: 6.5 points of average risk (40.67 -> 34.17), posture 57 -> 63",
        "  - S1: risk 39 -> 0, objective_reached -> contained",
        "dynamic_arp_inspection is false on SWSEC-2",
        "```\nip arp inspection vlan 10,50\n```",
        "- [S1] MITRE ATT&CK T1557.002: https://attack.mitre.org/techniques/T1557/002",
        "- [S3] MITRE D3FEND D3-NTA: https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis",
    ):
        assert expected in first, expected
    assert "**Before you apply**" not in first

    third = plan.split("## 3.")[1]
    assert "**Before you apply**\n\n- The twin models attack paths, not business traffic." in third
    assert "deny tcp from zone server to zone server port 5432\n# place before rule 1 on FW-INT" in third

    for item in await repository.list_remediations(acme_id):
        if item.status == RemediationStatus.VERIFIED:
            assert item.title in plan and item.config_snippet in plan
            assert all(citation.source_url in plan for citation in item.citations)


async def test_export_marks_applied_and_stale_fixes(acme_id: str) -> None:
    found = {**await generate(acme_id, "S1"), **await generate(acme_id, "S4")}
    await verify.verify(found[DAI].id)
    await verify.verify(found[LOCKOUT].id)
    await approval.decide(found[DAI].id, RemediationUpdate(status="approved", actor="alice"))

    network = await twin_repository.get_network(acme_id)
    plan = render_change_plan(network, await repository.list_remediations(acme_id))
    headings = [line for line in plan.splitlines() if line.startswith("## ")]
    assert headings == [f"## 1. {LOCKOUT}", f"## 2. {DAI}"]
    assert "- Status: verified on network version 1; the twin is now at version 2, so verify again before approving" in plan
    assert "- Status: applied to the twin" in plan
    assert "- none: the knowledge base had no source for this fix" in plan
