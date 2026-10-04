"""MongoDB access: client lifecycle, collection names, indexes and health ping."""

import logging
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ASCENDING

from app.core.config import get_settings

logger = logging.getLogger(__name__)

NETWORKS = "networks"
ASSETS = "assets"
LINKS = "links"
CONTROLS = "controls"
SIMULATION_RUNS = "simulation_runs"
FINDINGS = "findings"
EXPLANATIONS = "explanations"
REMEDIATIONS = "remediations"
AUDIT_LOG = "audit_log"
POSTURE_SNAPSHOTS = "posture_snapshots"

_client: AsyncIOMotorClient | None = None
_database: AsyncIOMotorDatabase | None = None


def connect() -> AsyncIOMotorDatabase:
    """Create the Motor client from settings and return the database handle."""
    global _client, _database
    settings = get_settings()
    _client = AsyncIOMotorClient(
        settings.mongo_uri,
        serverSelectionTimeoutMS=settings.mongo_timeout_ms,
        tz_aware=True,
    )
    _database = _client[settings.mongo_db]
    return _database


def close() -> None:
    """Close the Motor client if one is open."""
    global _client, _database
    if _client is not None:
        _client.close()
    _client = None
    _database = None


def set_database(database: Any | None) -> None:
    """Replace the active database handle. Used by tests to inject a mock database."""
    global _database
    _database = database


def get_database() -> AsyncIOMotorDatabase:
    """Return the active database handle, connecting on first use."""
    if _database is None:
        return connect()
    return _database


def collection(name: str) -> AsyncIOMotorCollection:
    """Return a collection of the active database by name."""
    return get_database()[name]


async def create_indexes() -> None:
    """Create every index the application relies on. Safe to call repeatedly."""
    database = get_database()
    await database[NETWORKS].create_index([("id", ASCENDING)], unique=True)
    for name in (ASSETS, LINKS, CONTROLS):
        await database[name].create_index([("id", ASCENDING)], unique=True)
        await database[name].create_index([("network_id", ASCENDING)])
        await database[name].create_index(
            [("network_id", ASCENDING), ("code", ASCENDING)], unique=True
        )
    runs = database[SIMULATION_RUNS]
    await runs.create_index([("id", ASCENDING)], unique=True)
    for field in ("network_id", "scenario_id", "created_at"):
        await runs.create_index([(field, ASCENDING)])
    findings = database[FINDINGS]
    await findings.create_index([("run_id", ASCENDING)], unique=True)
    await findings.create_index([("network_id", ASCENDING)])
    explanations = database[EXPLANATIONS]
    await explanations.create_index([("run_id", ASCENDING)], unique=True)
    await explanations.create_index([("network_id", ASCENDING)])
    remediations = database[REMEDIATIONS]
    await remediations.create_index([("id", ASCENDING)], unique=True)
    for field in ("network_id", "run_id"):
        await remediations.create_index([(field, ASCENDING)])
    audit_log = database[AUDIT_LOG]
    await audit_log.create_index([("id", ASCENDING)], unique=True)
    await audit_log.create_index([("network_id", ASCENDING), ("at", ASCENDING)])
    await database[POSTURE_SNAPSHOTS].create_index(
        [("network_id", ASCENDING), ("network_version", ASCENDING)], unique=True
    )
    logger.info("mongo indexes ensured")


async def ping() -> bool:
    """Return True when MongoDB answers a ping, False otherwise."""
    try:
        await get_database().command("ping")
    except Exception:  # noqa: BLE001 - any failure means the database is unreachable
        return False
    return True
