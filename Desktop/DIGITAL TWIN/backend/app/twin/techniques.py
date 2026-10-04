"""ATT&CK technique catalog, loaded once from data/attack/techniques.yaml."""

from functools import lru_cache

import yaml

from app.core.config import get_settings
from app.core.errors import NotFound
from app.models.enums import Tactic
from app.models.technique import Technique


@lru_cache
def _catalog() -> dict[str, Technique]:
    """Read and validate the catalog file. Cached for the life of the process."""
    path = get_settings().techniques_file
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    catalog: dict[str, Technique] = {}
    for entry in raw["techniques"]:
        technique = Technique.model_validate(entry)
        if technique.id in catalog:
            raise ValueError(f"duplicate technique id {technique.id} in {path}")
        catalog[technique.id] = technique
    return catalog


def get(technique_id: str) -> Technique:
    """Return one technique by id. Raises NotFound for unknown ids."""
    technique = _catalog().get(technique_id)
    if technique is None:
        raise NotFound(
            f"Technique {technique_id} is not in the catalog", {"technique_id": technique_id}
        )
    return technique


def all() -> list[Technique]:  # noqa: A001 - name fixed by the project specification
    """Return every technique in catalog order."""
    return list(_catalog().values())


def by_tactic(tactic: Tactic | str) -> list[Technique]:
    """Return the techniques that belong to one tactic."""
    wanted = Tactic(tactic)
    return [technique for technique in _catalog().values() if technique.tactic == wanted]
