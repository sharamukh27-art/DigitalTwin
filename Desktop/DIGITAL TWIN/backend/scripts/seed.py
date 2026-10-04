"""Seed the API with the ACME Corp sample network.

Usage:
    python scripts/seed.py [--api-url http://localhost:8000] [--file path/to/network.json]

The API base URL can also be set with the API_URL environment variable.
"""

import argparse
import os
import sys
from pathlib import Path

import httpx

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "data" / "sample_networks" / "acme_corp.json"
DEFAULT_API_URL = os.environ.get("API_URL", "http://localhost:8000")


def parse_args() -> argparse.Namespace:
    """Read command line options."""
    parser = argparse.ArgumentParser(description="Import a sample network through the API.")
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="Base URL of the running API")
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE, help="Twin file to import")
    return parser.parse_args()


def seed(api_url: str, file_path: Path) -> int:
    """Post the file to the import endpoint. Returns a process exit code."""
    endpoint = f"{api_url.rstrip('/')}/api/v1/networks/import"
    with file_path.open("rb") as handle:
        try:
            response = httpx.post(
                endpoint, files={"file": (file_path.name, handle, "application/json")}, timeout=30.0
            )
        except httpx.HTTPError as exc:
            print(f"Could not reach the API at {endpoint}: {exc}", file=sys.stderr)
            return 1

    body = response.json()
    if response.status_code != 201:
        error = body.get("error", {})
        print(f"Import failed ({response.status_code}): {error.get('message')}", file=sys.stderr)
        for message in error.get("details", {}).get("errors", []):
            print(f"  - {message}", file=sys.stderr)
        return 1

    print(f"Imported {file_path.name} with {len(body['errors'])} errors")
    print(f"  network_id:     {body['network_id']}")
    print(f"  assets_created: {body['assets_created']}")
    print(f"  links_created:  {body['links_created']}")
    print(f"  controls_created: {body['controls_created']}")
    return 0


if __name__ == "__main__":
    arguments = parse_args()
    sys.exit(seed(arguments.api_url, arguments.file))
