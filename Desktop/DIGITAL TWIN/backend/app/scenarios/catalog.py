"""Scenario library, loaded once from data/scenarios/*.yaml and validated."""

import json
from functools import lru_cache
from pathlib import Path

import yaml

from app.core.config import get_settings
from app.core.errors import NotFound
from app.models.scenario import Scenario
from app.twin import techniques


def _reference_codes() -> set[str]:
    """Return the asset codes of the sample network the library is written for."""
    with get_settings().reference_network_file.open("r", encoding="utf-8") as handle:
        return {asset["code"] for asset in json.load(handle)["assets"]}


def validate_scenario(scenario: Scenario, known_codes: set[str]) -> list[str]:
    """Return every problem with a scenario's techniques and asset codes.

    Each step's technique must exist in the technique catalog, and its tactic and
    layer must match the catalog. Every asset code must exist in `known_codes`.
    """
    problems: list[str] = []
    referenced = [("entry", scenario.entry.asset_code), ("goal", scenario.goal.target_code)]
    for step in scenario.steps:
        label = f"step {step.order}"
        referenced.append((label, step.target_code))
        try:
            technique = techniques.get(step.technique_id)
        except NotFound:
            problems.append(f"{label}: unknown technique {step.technique_id}")
            continue
        if step.tactic != technique.tactic:
            problems.append(
                f"{label}: tactic {step.tactic.value} does not match "
                f"{technique.id} ({technique.tactic.value})"
            )
        if step.layer != technique.osi_layer:
            problems.append(
                f"{label}: layer {step.layer} does not match {technique.id} (layer {technique.osi_layer})"
            )
    for label, code in referenced:
        if code is not None and code not in known_codes:
            problems.append(f"{label}: unknown asset code {code}")
    return problems


def load_scenarios(directory: Path, known_codes: set[str]) -> dict[str, Scenario]:
    """Load every scenario file of a folder, keyed by id. Raises ValueError on any problem."""
    scenarios: dict[str, Scenario] = {}
    codes: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as handle:
            scenario = Scenario.model_validate(yaml.safe_load(handle))
        problems = validate_scenario(scenario, known_codes)
        if scenario.id in scenarios:
            problems.append(f"duplicate scenario id {scenario.id}")
        if scenario.code in codes:
            problems.append(f"duplicate scenario code {scenario.code}")
        if problems:
            raise ValueError(f"{path.name}: " + "; ".join(problems))
        scenarios[scenario.id] = scenario
        codes.add(scenario.code)
    return scenarios


@lru_cache
def _library() -> dict[str, Scenario]:
    """Load the scenario library. Cached for the life of the process."""
    return load_scenarios(get_settings().scenarios_dir, _reference_codes())


def all() -> list[Scenario]:  # noqa: A001 - mirrors the technique catalog API
    """Return every scenario ordered by code."""
    return sorted(_library().values(), key=lambda scenario: scenario.code)


def get(scenario_ref: str) -> Scenario:
    """Return a scenario by id or code. Raises NotFound for unknown values."""
    library = _library()
    if scenario_ref in library:
        return library[scenario_ref]
    for scenario in library.values():
        if scenario.code == scenario_ref:
            return scenario
    raise NotFound(f"Scenario {scenario_ref} not found", {"scenario_id": scenario_ref})
