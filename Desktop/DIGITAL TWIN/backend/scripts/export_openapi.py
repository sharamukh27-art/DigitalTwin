"""Write the API's OpenAPI schema to a file, without starting a server.

Usage:
    python scripts/export_openapi.py <output.json>
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import create_app  # noqa: E402


def main() -> int:
    """Dump the schema of the FastAPI app to the path given on the command line."""
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    target = Path(sys.argv[1])
    target.write_text(json.dumps(create_app().openapi(), indent=2), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
