"""Build the knowledge base index from the sources on disk.

Usage:
    python scripts/kb_ingest.py

Reads data/knowledge_base/raw/ (run kb_download.py first) and
data/knowledge_base/org_policies/*.md, then replaces the Chroma collection at
CHROMA_PATH. Running it again replaces the index; it never duplicates chunks.
The first run downloads the embedding model from huggingface.co.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.rag.ingest import build_index  # noqa: E402


def main() -> int:
    """Build the index and print a count per source. Returns 0 when anything was indexed."""
    summary = build_index()
    print(f"Embedding model: {summary.embedding_model}")
    print(f"{'source':<32}{'documents':>10}{'chunks':>10}")
    for label, documents in summary.documents_by_source.items():
        print(f"{label:<32}{documents:>10}{summary.chunks_by_source.get(label, 0):>10}")
    print(f"{'total':<32}{sum(summary.documents_by_source.values()):>10}{summary.total_chunks:>10}")
    for note in summary.skipped_sources:
        print(f"skipped: {note}")
    print(f"Ingested at {summary.ingested_at.isoformat()}")
    return 0 if summary.total_chunks else 1


if __name__ == "__main__":
    sys.exit(main())
