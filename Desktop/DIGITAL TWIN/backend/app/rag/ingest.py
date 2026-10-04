"""Ingest: load whichever sources are present, chunk, embed and store them."""

import json
import logging
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.rag import sources
from app.rag.chunking import chunk_documents
from app.rag.documents import Document, IngestSummary
from app.rag.embedding import Embedder, get_embedder
from app.rag.store import KnowledgeStore

logger = logging.getLogger(__name__)

ATTACK_FILE = "enterprise-attack.json"
D3FEND_FILE = "d3fend.json"
NIST_FILE = "NIST_SP-800-53_rev5_catalog.json"

_JSON_SOURCES: tuple[tuple[str, str, Callable[[dict[str, Any]], list[Document]]], ...] = (
    (sources.ATTACK_SOURCE, ATTACK_FILE, sources.parse_attack),
    (sources.D3FEND_SOURCE, D3FEND_FILE, sources.parse_d3fend),
    (sources.NIST_SOURCE, NIST_FILE, sources.parse_nist),
)


def load_documents(raw_dir: Path, policies_dir: Path) -> tuple[dict[str, list[Document]], list[str]]:
    """Parse every source that is present.

    Returns (documents by source label, labels of sources that were missing or
    unreadable). A missing or broken source is skipped, never fatal.
    """
    loaded: dict[str, list[Document]] = {}
    skipped: list[str] = []
    for label, filename, parser in _JSON_SOURCES:
        path = raw_dir / filename
        if not path.is_file():
            skipped.append(f"{label}: {filename} not found")
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                loaded[label] = parser(json.load(handle))
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("knowledge base source could not be parsed", extra={"source": label})
            skipped.append(f"{label}: could not be parsed ({exc})")

    policies: list[Document] = []
    for path in sorted(policies_dir.glob("*.md")) if policies_dir.is_dir() else []:
        policies.extend(sources.parse_policy(path))
    if policies:
        loaded[sources.POLICY_SOURCE] = policies
    else:
        skipped.append(f"{sources.POLICY_SOURCE}: no .md files in {policies_dir.name}")
    skipped.append("CIS Controls: no machine-readable source is configured")
    return loaded, skipped


def build_index(
    raw_dir: Path | None = None,
    policies_dir: Path | None = None,
    store: KnowledgeStore | None = None,
    embedder: Embedder | None = None,
) -> IngestSummary:
    """Build the index from the sources on disk, replacing whatever was indexed before.

    Idempotent: the collection is replaced, so running this twice gives the same index.
    """
    settings = get_settings()
    store = store or KnowledgeStore()
    embedder = embedder or get_embedder()
    loaded, skipped = load_documents(raw_dir or settings.kb_raw_dir, policies_dir or settings.kb_policies_dir)

    documents = [document for label in sorted(loaded) for document in loaded[label]]
    chunks = chunk_documents(documents, settings.chunk_tokens, settings.chunk_overlap_tokens)
    embeddings = embedder.embed([chunk.text for chunk in chunks]) if chunks else []
    ingested_at = store.replace_all(chunks, embeddings, embedder.name)

    document_source = {document.id: label for label, items in loaded.items() for document in items}
    summary = IngestSummary(
        documents_by_source={label: len(items) for label, items in sorted(loaded.items())},
        chunks_by_source=dict(sorted(Counter(document_source[chunk.document_id] for chunk in chunks).items())),
        total_chunks=len(chunks),
        skipped_sources=skipped,
        embedding_model=embedder.name,
        ingested_at=ingested_at,
    )
    logger.info("knowledge base ingested", extra={"total_chunks": summary.total_chunks})
    return summary
