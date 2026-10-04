"""Capability catalog, loaded once from data/controls/capabilities.yaml."""

from functools import lru_cache
from typing import Any

import yaml
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.models.control import CONFIG_MODELS, ConfigModel
from app.models.enums import CapabilityAction, ControlType, EnforcementMode, IdsMode
from app.twin import techniques

_DETECT_ONLY_MODES = (EnforcementMode.DETECT, IdsMode.IDS)
_REQUIREMENT_OPERATORS = {"contains", "not_null"}


class Capability(BaseModel):
    """What one control type can do about one technique."""

    action: CapabilityAction
    confidence: float = Field(ge=0.0, le=1.0)
    requires: dict[str, Any] = Field(default_factory=dict)


class CapabilityCatalog(BaseModel):
    """Parsed content of the capability catalog file."""

    min_layer: dict[ControlType, int]
    capabilities: dict[ControlType, dict[str, Capability]]


def _check(catalog: CapabilityCatalog) -> None:
    """Reject a catalog that names unknown techniques, config keys or operators."""
    missing_layers = [item.value for item in ControlType if item not in catalog.min_layer]
    if missing_layers:
        raise ValueError(f"min_layer is missing control types: {', '.join(missing_layers)}")
    for control_type, entries in catalog.capabilities.items():
        config_fields = CONFIG_MODELS[control_type].model_fields
        for technique_id, capability in entries.items():
            techniques.get(technique_id)
            for key, expected in capability.requires.items():
                if key not in config_fields:
                    raise ValueError(
                        f"{control_type.value}/{technique_id} requires unknown config key '{key}'"
                    )
                if isinstance(expected, dict) and set(expected) - _REQUIREMENT_OPERATORS:
                    raise ValueError(
                        f"{control_type.value}/{technique_id} uses an unknown requirement operator"
                    )


@lru_cache
def _catalog() -> CapabilityCatalog:
    """Read and validate the catalog file. Cached for the life of the process."""
    with get_settings().capabilities_file.open("r", encoding="utf-8") as handle:
        catalog = CapabilityCatalog.model_validate(yaml.safe_load(handle))
    _check(catalog)
    return catalog


def min_layer(control_type: ControlType) -> int:
    """Return the lowest OSI layer a control type can see."""
    return _catalog().min_layer[control_type]


def capabilities_for(control_type: ControlType) -> dict[str, Capability]:
    """Return every catalog entry of a control type, keyed by technique id."""
    return dict(_catalog().capabilities.get(control_type, {}))


def get_capability(control_type: ControlType, technique_id: str) -> Capability | None:
    """Return the catalog entry for a control type and technique, or None."""
    return _catalog().capabilities.get(control_type, {}).get(technique_id)


def _show(value: Any) -> str:
    """Render a config value the way it appears in JSON."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def failed_requirements(capability: Capability, config: ConfigModel) -> list[str]:
    """Return one message per `requires` condition the config does not meet."""
    values = config.model_dump(mode="json")
    failures: list[str] = []
    for key, expected in capability.requires.items():
        actual = values.get(key)
        if isinstance(expected, dict):
            if "contains" in expected and expected["contains"] not in (actual or []):
                failures.append(f"{key} does not contain {_show(expected['contains'])}")
            if expected.get("not_null") and actual is None:
                failures.append(f"{key} is not set")
        elif actual != expected:
            failures.append(f"{key} is {_show(actual)}")
    return failures


def effective_action(
    capability: Capability, config: ConfigModel
) -> tuple[CapabilityAction, CapabilityAction | None]:
    """Return (action, downgraded_from).

    A "block" capability becomes "detect" when the control runs in a detect-only
    mode. `downgraded_from` is then "block", otherwise None.
    """
    mode = getattr(config, "mode", None)
    if capability.action == CapabilityAction.BLOCK and mode in _DETECT_ONLY_MODES:
        return CapabilityAction.DETECT, CapabilityAction.BLOCK
    return capability.action, None
