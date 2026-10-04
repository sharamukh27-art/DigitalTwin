"""Download the public knowledge base sources into data/knowledge_base/raw/.

Usage:
    python scripts/kb_download.py [--force]

Only hosts in ALLOWED_HOSTS are contacted. A source that cannot be fetched is logged
and skipped; the others still download. Existing files are kept unless --force is given.
"""

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings  # noqa: E402
from app.rag.ingest import ATTACK_FILE, D3FEND_FILE, NIST_FILE  # noqa: E402

ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com", "d3fend.mitre.org"})

SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "MITRE ATT&CK Enterprise (STIX)",
        ATTACK_FILE,
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json",
    ),
    ("MITRE D3FEND ontology", D3FEND_FILE, "https://d3fend.mitre.org/ontologies/d3fend.json"),
    (
        "NIST SP 800-53 Rev 5 (OSCAL)",
        NIST_FILE,
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
        "NIST_SP-800-53_rev5_catalog.json",
    ),
)
SKIPPED_SOURCES = ("CIS Controls: no openly licensed machine-readable source, not downloaded",)


def download(url: str, target: Path) -> int:
    """Stream a URL to a file and return the number of bytes written.

    Raises ValueError for a host outside the allowlist and httpx.HTTPError on failure.
    The file is written under a temporary name first, so a failed download leaves no
    partial file behind.
    """
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"host {host} is not in the download allowlist")
    partial = target.with_suffix(target.suffix + ".part")
    written = 0
    try:
        with httpx.stream("GET", url, timeout=120.0, follow_redirects=False) as response:
            response.raise_for_status()
            with partial.open("wb") as handle:
                for block in response.iter_bytes():
                    handle.write(block)
                    written += len(block)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)
    return written


def main() -> int:
    """Download every source. Returns 0 when at least one source is present afterwards."""
    parser = argparse.ArgumentParser(description="Download knowledge base sources.")
    parser.add_argument("--force", action="store_true", help="Download again even if the file exists")
    arguments = parser.parse_args()

    raw_dir = get_settings().kb_raw_dir
    raw_dir.mkdir(parents=True, exist_ok=True)
    present = 0
    for label, filename, url in SOURCES:
        target = raw_dir / filename
        if target.is_file() and not arguments.force:
            print(f"kept     {label}: {filename} already present")
            present += 1
            continue
        try:
            size = download(url, target)
        except (httpx.HTTPError, ValueError, OSError) as exc:
            print(f"FAILED   {label}: {exc}", file=sys.stderr)
            continue
        print(f"fetched  {label}: {filename} ({size / 1_000_000:.1f} MB)")
        present += 1
    for note in SKIPPED_SOURCES:
        print(f"skipped  {note}")
    print(f"{present} of {len(SOURCES)} sources present in {raw_dir}")
    return 0 if present else 1


if __name__ == "__main__":
    sys.exit(main())
