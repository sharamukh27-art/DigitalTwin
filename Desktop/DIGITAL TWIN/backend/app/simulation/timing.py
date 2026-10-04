"""Time model: how long each kind of step takes, with deterministic jitter."""

import random

from app.models.enums import Tactic

JITTER = 0.2

BASE_SECONDS: dict[Tactic, int] = {
    Tactic.RECONNAISSANCE: 300,
    Tactic.RESOURCE_DEVELOPMENT: 600,
    Tactic.INITIAL_ACCESS: 600,
    Tactic.EXECUTION: 120,
    Tactic.PERSISTENCE: 300,
    Tactic.PRIVILEGE_ESCALATION: 600,
    Tactic.DEFENSE_EVASION: 300,
    Tactic.CREDENTIAL_ACCESS: 900,
    Tactic.DISCOVERY: 300,
    Tactic.LATERAL_MOVEMENT: 600,
    Tactic.COLLECTION: 900,
    Tactic.COMMAND_AND_CONTROL: 120,
    Tactic.EXFILTRATION: 1200,
    Tactic.IMPACT: 1800,
}


def step_seconds(tactic: Tactic, rng: random.Random) -> int:
    """Return the duration of a step: the tactic's base time jittered by up to 20% either way."""
    return round(BASE_SECONDS[tactic] * rng.uniform(1 - JITTER, 1 + JITTER))
