"""Scenario model validation and the scenario library."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from app.core.errors import NotFound
from app.models.enums import EffectKind, SelectorKind
from app.models.scenario import ScenarioEntry, ScenarioGoal, parse_effect, parse_selector
from app.scenarios import catalog
from tests.sim import make_scenario, step


def test_parse_effect() -> None:
    assert parse_effect("gain_foothold") == (EffectKind.GAIN_FOOTHOLD, None)
    assert parse_effect("move_to:APP-01") == (EffectKind.MOVE_TO, "APP-01")
    for bad in ("fly", "move_to", "move_to:", "read_data:FS-01"):
        with pytest.raises(ValueError):
            parse_effect(bad)


def test_parse_selector() -> None:
    assert parse_selector("next_hop_toward_goal") == (SelectorKind.NEXT_HOP_TOWARD_GOAL, None)
    assert parse_selector("current_position") == (SelectorKind.CURRENT_POSITION, None)
    assert parse_selector("any_in_zone:server") == (SelectorKind.ANY_IN_ZONE, "server")
    assert parse_selector("role:file_server") == (SelectorKind.ROLE, "file_server")
    for bad in ("nearest", "any_in_zone:moon", "role:toaster", "role", "next_hop_toward_goal:x"):
        with pytest.raises(ValueError):
            parse_selector(bad)


def test_entry_needs_exactly_one_of_zone_or_asset() -> None:
    assert ScenarioEntry(zone="internet").asset_code is None
    assert ScenarioEntry(asset_code="WS-03").zone is None
    with pytest.raises(ValidationError):
        ScenarioEntry()
    with pytest.raises(ValidationError):
        ScenarioEntry(zone="internet", asset_code="WS-03")


def test_goal_fields_must_fit_kind() -> None:
    assert ScenarioGoal(kind="exfiltrate").target_code is None
    with pytest.raises(ValidationError, match="target_code"):
        ScenarioGoal(kind="reach_asset")
    for kind in ("reach_any_critical", "encrypt"):
        with pytest.raises(ValidationError, match="min_criticality"):
            ScenarioGoal(kind=kind)
    with pytest.raises(ValidationError):
        ScenarioGoal(kind="encrypt", min_criticality=6)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({}, "exactly one of target_code or target_selector"),
        ({"target_code": "B", "target_selector": "current_position"}, "exactly one"),
        ({"target_selector": "teleport"}, "unknown target selector"),
        ({"target_code": "B", "on_success": ["win"]}, "unknown effect"),
        ({"target_code": "B", "preconditions": ["move_to:B"]}, "cannot be a precondition"),
        ({"target_code": "B", "bypasses": ["waf"], "bypass_reason": "x"}, "only list firewall and segmentation"),
        ({"target_code": "B", "bypasses": ["firewall"]}, "bypass_reason is required"),
        ({"target_code": "B", "port": 0}, "port"),
    ],
)
def test_bad_steps_are_rejected(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        make_scenario([step(1, **fields)])


def test_steps_must_be_numbered_in_order() -> None:
    make_scenario([step(1, target_code="B"), step(2, target_code="B")])
    with pytest.raises(ValidationError, match="ordered 1, 2, 3"):
        make_scenario([step(1, target_code="B"), step(3, target_code="B")])
    with pytest.raises(ValidationError):
        make_scenario([])


def test_library_has_the_six_scenarios() -> None:
    scenarios = catalog.all()
    assert [(item.code, item.name) for item in scenarios] == [
        ("S1", "mac-spoof-pivot"),
        ("S2", "phish-to-fileserver"),
        ("S3", "sqli-web-to-db"),
        ("S4", "vpn-bruteforce"),
        ("S5", "ransomware-smb"),
        ("S6", "insider-exfil"),
    ]
    assert len({item.id for item in scenarios}) == 6
    profiles = {item.code: item.attacker_profile.value for item in scenarios}
    assert profiles == {
        "S1": "compromised_device", "S2": "outsider", "S3": "outsider",
        "S4": "outsider", "S5": "compromised_device", "S6": "insider",
    }
    goals = {item.code: item.goal.kind.value for item in scenarios}
    assert goals == {
        "S1": "reach_asset", "S2": "reach_asset", "S3": "reach_asset",
        "S4": "reach_any_critical", "S5": "encrypt", "S6": "exfiltrate",
    }
    techniques_used = {item.code: [s.technique_id for s in item.steps] for item in scenarios}
    assert techniques_used["S1"][:3] == ["T1557.002", "T1599", "T1046"]
    assert techniques_used["S2"] == ["T1566.001", "T1078", "T1021.002", "T1005"]
    assert techniques_used["S4"] == ["T1133", "T1110", "T1078"]
    assert techniques_used["S5"] == ["T1021.002", "T1003", "T1486"]
    assert techniques_used["S6"] == ["T1005", "T1048"]


def test_get_by_id_and_code() -> None:
    by_code = catalog.get("S3")
    assert catalog.get(by_code.id) is by_code
    with pytest.raises(NotFound):
        catalog.get("S99")


def test_validate_scenario_reports_every_problem() -> None:
    scenario = make_scenario(
        [
            step(1, "T1190", target_code="GHOST"),
            step(2, "T1190", target_code="WEB-01", tactic="impact"),
            step(3, "T1190", target_code="WEB-01", layer=2),
            {**step(4, "T1190", target_selector="role:workstation"), "technique_id": "T9999"},
        ],
        entry="NOWHERE",
        goal={"kind": "reach_asset", "target_code": "ALSO-GHOST"},
    )
    problems = catalog.validate_scenario(scenario, {"WEB-01"})
    assert problems == [
        "step 2: tactic impact does not match T1190 (initial_access)",
        "step 3: layer 2 does not match T1190 (layer 7)",
        "step 4: unknown technique T9999",
        "entry: unknown asset code NOWHERE",
        "goal: unknown asset code ALSO-GHOST",
        "step 1: unknown asset code GHOST",
    ]


def test_every_library_scenario_is_valid_against_the_sample() -> None:
    known = catalog._reference_codes()
    assert len(known) == 25
    for scenario in catalog.all():
        assert catalog.validate_scenario(scenario, known) == []


def test_load_scenarios_rejects_bad_and_duplicate_files(tmp_path: Path) -> None:
    good = make_scenario([step(1, target_code="B")]).model_dump(mode="json")
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(good))
    assert list(catalog.load_scenarios(tmp_path, {"A", "B"})) == [good["id"]]

    (tmp_path / "b.yaml").write_text(yaml.safe_dump(good))
    with pytest.raises(ValueError, match="b.yaml: duplicate scenario id"):
        catalog.load_scenarios(tmp_path, {"A", "B"})

    (tmp_path / "b.yaml").unlink()
    with pytest.raises(ValueError, match="a.yaml: goal: unknown asset code B"):
        catalog.load_scenarios(tmp_path, {"A"})
