"""Posture, sandboxes, patches and what-if comparison."""

from typing import Any

import pytest

from app.analysis import posture as posture_module
from app.analysis import whatif
from app.controls import repository as control_repository
from app.core import db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.models.analysis import ScenarioRisk, WeakestLink
from app.models.network import Network
from app.models.whatif import PatchOp
from app.simulation import engine
from app.simulation import repository as run_repository
from app.twin import graph as twin_graph
from app.twin import loader, repository
from app.twin.versioning import bump_version

DAI_ON = [PatchOp(target="control", code="SWSEC-2", set={"config.dynamic_arp_inspection": True})]


def scenario_risk(code: str, score: int, link: tuple[str, str] | None = None) -> ScenarioRisk:
    return ScenarioRisk(
        scenario_code=code,
        run_id=f"run-{code}",
        risk_score=score,
        band="low",
        containment="contained",
        weakest_link=WeakestLink(kind=link[0], ref=link[1], step_order=1, explanation="") if link else None,
    )


async def count(collection: str, **query: Any) -> int:
    return await db.collection(collection).count_documents(query)


def test_posture_formula() -> None:
    risks = [
        scenario_risk("S2", 20, ("blind_spot", "T1005")),
        scenario_risk("S1", 60, ("missed_control", "WAF-01")),
        scenario_risk("S3", 40, ("missed_control", "WAF-01")),
        scenario_risk("S4", 0),
    ]
    result = posture_module.build_posture("net", 3, risks, coverage_percent=80.0, stale_scenarios=["S6", "S5"])

    assert result.average_risk == 30.0
    assert result.breakdown.model_dump() == {
        "average_risk": 30.0,
        "base_score": 70.0,
        "coverage_percent": 80.0,
        "coverage_factor": 0.95,
        "formula": posture_module.FORMULA,
        "constants": {"coverage_floor": 0.75, "coverage_span": 0.25},
    }
    assert result.posture_score == 67  # round(70 x 0.95) = round(66.5)
    assert [item.scenario_code for item in result.per_scenario] == ["S1", "S2", "S3", "S4"]
    assert [item.scenario_code for item in result.top_risks] == ["S1", "S3", "S2"]
    assert [(item.ref, item.count, item.scenario_codes) for item in result.worst_weakest_links] == [
        ("WAF-01", 2, ["S1", "S3"]),
        ("T1005", 1, ["S2"]),
    ]
    assert result.stale_scenarios == ["S5", "S6"]
    assert (result.network_id, result.network_version) == ("net", 3)


def test_posture_at_the_extremes() -> None:
    assert posture_module.build_posture("n", 1, [scenario_risk("S1", 0)], 100.0).posture_score == 100
    assert posture_module.build_posture("n", 1, [scenario_risk("S1", 0)], 0.0).posture_score == 75
    assert posture_module.build_posture("n", 1, [scenario_risk("S1", 100)], 100.0).posture_score == 0
    empty = posture_module.build_posture("n", 1, [], 50.0)
    assert (empty.average_risk, empty.posture_score, empty.top_risks) == (0.0, 88, [])


async def test_posture_of_the_sample_runs_missing_scenarios(acme_id: str) -> None:
    result = await posture_module.posture(acme_id)
    assert {item.scenario_code: item.risk_score for item in result.per_scenario} == {
        "S1": 39, "S2": 0, "S3": 51, "S4": 46, "S5": 52, "S6": 56,
    }
    assert {item.scenario_code: item.band.value for item in result.per_scenario} == {
        "S1": "medium", "S2": "low", "S3": "high", "S4": "medium", "S5": "high", "S6": "high",
    }
    assert (result.average_risk, result.coverage_percent, result.posture_score) == (40.67, 85.7, 57)
    assert result.breakdown.coverage_factor == 0.9643
    assert [item.scenario_code for item in result.top_risks] == ["S6", "S5", "S3"]
    assert result.stale_scenarios == []
    assert len(result.worst_weakest_links) == 5
    assert await count(db.SIMULATION_RUNS) == 6

    again = await posture_module.posture(acme_id)
    assert again == result
    assert await count(db.SIMULATION_RUNS) == 6


async def test_posture_without_refresh_reports_stale_scenarios(acme_id: str) -> None:
    cold = await posture_module.posture(acme_id, refresh=False)
    assert cold.stale_scenarios == ["S1", "S2", "S3", "S4", "S5", "S6"]
    assert (cold.per_scenario, cold.average_risk, cold.posture_score) == ([], 0.0, 96)
    assert await count(db.SIMULATION_RUNS) == 0

    await engine.run(acme_id, "S3")
    partial = await posture_module.posture(acme_id, refresh=False)
    assert [item.scenario_code for item in partial.per_scenario] == ["S3"]
    assert len(partial.stale_scenarios) == 5

    await bump_version(acme_id)
    after_change = await posture_module.posture(acme_id, refresh=False)
    assert after_change.network_version == 2
    assert len(after_change.stale_scenarios) == 6


async def test_posture_lists_scenarios_that_cannot_run_as_stale(database: Any) -> None:
    network = await repository.insert_network(Network(name="empty"))
    result = await posture_module.posture(network.id)
    assert len(result.stale_scenarios) == 6
    assert (result.per_scenario, result.coverage_percent, result.posture_score) == ([], 0.0, 75)
    with pytest.raises(NotFound):
        await posture_module.posture("missing")


async def test_clone_to_sandbox(acme_id: str) -> None:
    await bump_version(acme_id)
    sandbox = await whatif.clone_to_sandbox(acme_id)
    original = await repository.get_network(acme_id)

    assert sandbox.is_sandbox is True
    assert sandbox.parent_network_id == acme_id
    assert (sandbox.version, original.version) == (2, 2)
    assert sandbox.id != acme_id and sandbox.name == "ACME Corp (sandbox)"
    assert (await repository.get_network(sandbox.id)) == sandbox

    old_assets = {asset.code: asset for asset in await repository.all_assets(acme_id)}
    new_assets = {asset.code: asset for asset in await repository.all_assets(sandbox.id)}
    assert set(new_assets) == set(old_assets) and len(new_assets) == 25
    assert not {asset.id for asset in new_assets.values()} & {asset.id for asset in old_assets.values()}
    ignore = {"id", "network_id", "created_at", "updated_at"}
    assert new_assets["DB-01"].model_dump(exclude=ignore) == old_assets["DB-01"].model_dump(exclude=ignore)

    new_ids = {asset.id for asset in new_assets.values()}
    links = await repository.all_links(sandbox.id)
    assert len(links) == 24
    assert all(link.source_asset_id in new_ids and link.target_asset_id in new_ids for link in links)

    controls = {control.code: control for control in await control_repository.all_controls(sandbox.id)}
    assert len(controls) == 14
    assert controls["WAF-01"].placement.asset_ids == [new_assets["WEB-01"].id]
    assert len(controls["EDR-01"].placement.asset_ids) == 12
    assert all(asset_id in new_ids for control in controls.values() for asset_id in control.placement.asset_ids)

    assert (await loader.export_network(sandbox.id)).model_dump(mode="json", exclude={"network"}) == (
        await loader.export_network(acme_id)
    ).model_dump(mode="json", exclude={"network"})

    await whatif.delete_sandbox(sandbox.id)
    assert await count(db.NETWORKS) == 1
    assert await count(db.ASSETS) == 25 and await count(db.LINKS) == 24 and await count(db.CONTROLS) == 14
    with pytest.raises(NotFound):
        await whatif.clone_to_sandbox("missing")


def test_set_path() -> None:
    document: dict[str, Any] = {"config": {"mode": "detect", "rules": [{"action": "allow"}, {"action": "deny"}]}, "enabled": True, "id": "x"}
    whatif.set_path(document, "config.mode", "block")
    whatif.set_path(document, "config.rules.1.action", "allow")
    whatif.set_path(document, "enabled", False)
    assert document == {"config": {"mode": "block", "rules": [{"action": "allow"}, {"action": "allow"}]}, "enabled": False, "id": "x"}

    for path, message in (
        ("config.nope", "no field 'nope'"),
        ("config.rules.5.action", "no list index '5'"),
        ("config.rules.first", "no list index 'first'"),
        ("config.mode.deeper", "below a plain value"),
        ("id", "'id' cannot be changed"),
        ("code", "'code' cannot be changed"),
    ):
        with pytest.raises(ValueError, match=message):
            whatif.set_path(document, path, 1)


async def test_apply_patch_changes_controls_and_assets_and_bumps_once(acme_id: str) -> None:
    sandbox = await whatif.clone_to_sandbox(acme_id)
    patch = [
        DAI_ON[0],
        PatchOp(target="control", code="FW-EDGE", set={"config.rules.0.action": "deny", "enabled": False}),
        PatchOp(target="control", code="EDR-01", set={"placement.asset_codes": ["FS-01", "DC-01"]}),
        PatchOp(target="asset", code="DB-01", set={"criticality": 3, "open_ports.0.port": 5433}),
    ]
    assert await whatif.apply_patch(sandbox.id, patch) == 2

    controls = {control.code: control for control in await control_repository.all_controls(sandbox.id)}
    assets = {asset.code: asset for asset in await repository.all_assets(sandbox.id)}
    assert controls["SWSEC-2"].config.dynamic_arp_inspection is True
    assert controls["SWSEC-2"].config.dhcp_snooping is True
    assert (controls["FW-EDGE"].config.rules[0].action.value, controls["FW-EDGE"].enabled) == ("deny", False)
    assert controls["EDR-01"].placement.asset_ids == [assets["FS-01"].id, assets["DC-01"].id]
    assert (assets["DB-01"].criticality, assets["DB-01"].open_ports[0].port) == (3, 5433)
    assert controls["SWSEC-2"].updated_at >= controls["SWSEC-2"].created_at

    real = {control.code: control for control in await control_repository.all_controls(acme_id)}
    assert real["SWSEC-2"].config.dynamic_arp_inspection is False
    assert (await repository.get_network(acme_id)).version == 1


async def test_apply_patch_reports_every_problem_and_writes_nothing(acme_id: str) -> None:
    sandbox = await whatif.clone_to_sandbox(acme_id)
    bad = [
        DAI_ON[0],
        PatchOp(target="control", code="NOPE", set={"enabled": False}),
        PatchOp(target="control", code="WAF-01", set={"config.mode": "sometimes"}),
        PatchOp(target="control", code="WAF-01", set={"config.typo": True}),
        PatchOp(target="control", code="EDR-01", set={"type": "waf"}),
        PatchOp(target="control", code="EDR-01", set={"placement.asset_codes": ["GHOST"]}),
        PatchOp(target="control", code="EDR-01", set={"placement.asset_codes": []}),
        PatchOp(target="asset", code="DB-01", set={"criticality": 9}),
        PatchOp(target="asset", code="DB-01", set={"colour": "red"}),
    ]
    with pytest.raises(ValidationFailed) as caught:
        await whatif.apply_patch(sandbox.id, bad)
    errors = caught.value.details["errors"]
    assert len(errors) == 8
    joined = "\n".join(errors)
    for expected in (
        "patch[1] (control NOPE): no control with code NOPE",
        "patch[2] (control WAF-01): Value error, config.mode: Input should be 'detect' or 'block'",
        "patch[3] (control WAF-01): unknown path 'config.typo': no field 'typo'",
        "patch[4] (control EDR-01): 'type' cannot be changed by a patch",
        "patch[5] (control EDR-01): 'placement.asset_codes' must be a list of asset codes of this network",
        "patch[6] (control EDR-01): host placement needs at least one asset",
        "patch[7] (asset DB-01): criticality: Input should be less than or equal to 5",
        "patch[8] (asset DB-01): unknown path 'colour': no field 'colour'",
    ):
        assert expected in joined

    controls = {control.code: control for control in await control_repository.all_controls(sandbox.id)}
    assert controls["SWSEC-2"].config.dynamic_arp_inspection is False
    assert (await repository.get_network(sandbox.id)).version == 1


async def test_patches_are_refused_on_a_real_network(acme_id: str) -> None:
    with pytest.raises(Conflict, match="only be applied to a sandbox"):
        await whatif.apply_patch(acme_id, DAI_ON)
    with pytest.raises(NotFound):
        await whatif.apply_patch("missing", DAI_ON)


async def test_whatif_dai_lowers_s1_flips_containment_and_worsens_nothing(acme_id: str) -> None:
    result = await whatif.whatif(acme_id, DAI_ON)

    assert [item.scenario_code for item in result.diff] == ["S1", "S2", "S3", "S4", "S5", "S6"]
    s1 = result.diff[0]
    assert (s1.risk_before, s1.risk_after, s1.delta) == (39, 0, -39)
    assert (s1.containment_before.value, s1.containment_after.value) == ("objective_reached", "contained")
    assert [(c.step_order, c.from_outcome and c.from_outcome.value, c.to_outcome and c.to_outcome.value) for c in s1.steps_changed] == [
        (1, "detected_not_blocked", "blocked"),
        (2, "detected_not_blocked", None),
        (3, "detected_not_blocked", None),
        (4, "detected_not_blocked", None),
        (5, "undetected", None),
    ]
    for other in result.diff[1:]:
        assert (other.delta, other.steps_changed) == (0, [])
        assert other.containment_before == other.containment_after

    assert result.summary.model_dump() == {
        "total_risk_delta": -39, "scenarios_improved": 1, "scenarios_worsened": 0, "scenarios_unchanged": 5,
    }
    assert (result.before.posture.posture_score, result.after.posture.posture_score) == (57, 63)
    assert result.before.posture.average_risk == 40.67
    assert result.before.posture.coverage_percent == result.after.posture.coverage_percent == 85.7
    assert (result.seed, result.sandbox_id, result.patch) == (42, None, DAI_ON)


async def test_whatif_leaves_the_real_network_untouched_and_deletes_the_sandbox(acme_id: str) -> None:
    await twin_graph.build_graph(acme_id)
    await whatif.whatif(acme_id, DAI_ON, scenario_ids=["S1"])

    assert await count(db.NETWORKS) == 1
    assert await count(db.ASSETS) == 25 and await count(db.LINKS) == 24 and await count(db.CONTROLS) == 14
    assert await count(db.SIMULATION_RUNS) == 0 and await count(db.FINDINGS) == 0
    assert (await repository.get_network(acme_id)).version == 1
    swsec = next(c for c in await control_repository.all_controls(acme_id) if c.code == "SWSEC-2")
    assert swsec.config.dynamic_arp_inspection is False
    assert {key[0] for key in twin_graph._CACHE} == {acme_id}


async def test_whatif_keep_keeps_the_patched_sandbox(acme_id: str) -> None:
    result = await whatif.whatif(acme_id, DAI_ON, scenario_ids=["S1", "S3"], keep=True)
    assert result.sandbox_id is not None
    assert [item.scenario_code for item in result.diff] == ["S1", "S3"]

    sandbox = await repository.get_network(result.sandbox_id)
    assert (sandbox.is_sandbox, sandbox.parent_network_id, sandbox.version) == (True, acme_id, 2)
    swsec = next(c for c in await control_repository.all_controls(sandbox.id) if c.code == "SWSEC-2")
    assert swsec.config.dynamic_arp_inspection is True

    runs, total = await run_repository.list_runs(sandbox.id, 50, 0)
    assert total == 4
    assert sorted((run.scenario_code, run.network_version) for run in runs) == [("S1", 1), ("S1", 2), ("S3", 1), ("S3", 2)]
    assert await count(db.FINDINGS, network_id=sandbox.id) == 4
    assert await count(db.SIMULATION_RUNS, network_id=acme_id) == 0

    await whatif.delete_sandbox(sandbox.id)
    assert await count(db.NETWORKS) == 1
    assert await count(db.SIMULATION_RUNS) == 0 and await count(db.FINDINGS) == 0


async def test_whatif_uses_the_same_seed_on_both_sides(acme_id: str) -> None:
    harmless = [PatchOp(target="control", code="BKP-01", set={"name": "Backups renamed"})]
    for seed in (42, 7):
        result = await whatif.whatif(acme_id, harmless, seed=seed, keep=True)
        assert result.summary.model_dump() == {
            "total_risk_delta": 0, "scenarios_improved": 0, "scenarios_worsened": 0, "scenarios_unchanged": 6,
        }
        assert all(item.steps_changed == [] for item in result.diff)
        assert result.before.posture.posture_score == result.after.posture.posture_score

        runs, _ = await run_repository.list_runs(result.sandbox_id, 50, 0)
        assert {run.seed for run in runs} == {seed}
        by_version: dict[str, dict[int, str]] = {}
        for run in runs:
            by_version.setdefault(run.scenario_code, {})[run.network_version] = "".join(
                step.model_dump_json() for step in run.step_results
            )
        assert all(versions[1] == versions[2] for versions in by_version.values())

        direct = await engine.run(acme_id, "S4", seed)
        sandbox_s4 = next(run for run in runs if run.scenario_code == "S4" and run.network_version == 1)
        without_ids = {"control_results": {"__all__": {"control_id"}}}
        assert [step.model_dump(exclude=without_ids) for step in sandbox_s4.step_results] == [
            step.model_dump(exclude=without_ids) for step in direct.step_results
        ]
        await whatif.delete_sandbox(result.sandbox_id)


async def test_whatif_with_a_bad_patch_or_scenario_cleans_up(acme_id: str) -> None:
    with pytest.raises(ValidationFailed, match="Patch is not valid"):
        await whatif.whatif(acme_id, [PatchOp(target="control", code="WAF-01", set={"config.mode": "x"})], keep=True)
    assert await count(db.NETWORKS) == 1 and await count(db.SIMULATION_RUNS) == 0

    with pytest.raises(NotFound):
        await whatif.whatif(acme_id, DAI_ON, scenario_ids=["S99"])
    with pytest.raises(NotFound):
        await whatif.whatif("missing", DAI_ON)
    assert await count(db.NETWORKS) == 1


async def test_whatif_can_make_things_worse(acme_id: str) -> None:
    weaker = [PatchOp(target="control", code="MAIL-01", set={"config.attachment_sandboxing": False})]
    result = await whatif.whatif(acme_id, weaker, scenario_ids=["S2"])
    only = result.diff[0]
    assert only.risk_before == 0 and only.risk_after > 0
    assert (only.containment_before.value, only.containment_after.value) == ("contained", "objective_reached")
    assert only.steps_changed[0].model_dump(mode="json") == {
        "step_order": 1, "from_outcome": "blocked", "to_outcome": "detected_not_blocked",
    }
    assert (result.summary.scenarios_worsened, result.summary.total_risk_delta) == (1, only.delta)
