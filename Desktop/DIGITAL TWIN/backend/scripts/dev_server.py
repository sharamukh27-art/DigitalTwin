"""Run the API on an in-memory MongoDB, for demos on a machine without MongoDB or Docker.

Usage:
    python scripts/dev_server.py [--port 8000] [--seed]

Everything is the real application except the database, which is mongomock-motor and
lives only in this process: all data is lost when it stops. With --seed the ACME
sample network is imported at startup. For anything beyond a demo, run MongoDB and
start the app with uvicorn instead.
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

from app.core import db  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.twin import loader  # noqa: E402

_DATABASE = AsyncMongoMockClient(tz_aware=True)["cyber_twin_demo"]


def _use_memory_database() -> None:
    """Point the application at the in-memory database for the life of the process."""
    db.connect = lambda: (db.set_database(_DATABASE), _DATABASE)[1]  # type: ignore[assignment]
    db.close = lambda: None  # type: ignore[assignment]
    db.set_database(_DATABASE)


async def _seed() -> None:
    sample = get_settings().reference_network_file
    result = await loader.import_network(sample.read_bytes(), sample.name)
    print(
        f"seeded {sample.name}: {result.assets_created} assets, {result.links_created} links, "
        f"{result.controls_created} controls (network {result.network_id})"
    )


def main() -> None:
    """Start the API with an in-memory database."""
    parser = argparse.ArgumentParser(description="Run the API on an in-memory database.")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--seed", action="store_true", help="Import the ACME sample network at startup")
    arguments = parser.parse_args()

    _use_memory_database()
    if arguments.seed:
        asyncio.run(_seed())
    from app.main import app

    print("in-memory database: data is lost when this process stops")
    uvicorn.run(app, host=arguments.host, port=arguments.port, log_level="warning")


if __name__ == "__main__":
    main()
