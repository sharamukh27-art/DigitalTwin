"""ChromaDB access: one persistent collection holding every knowledge base chunk."""

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Any

import threading

import chromadb
from chromadb.config import Settings as ChromaSettings
from chromadb.errors import NotFoundError

from app.core.config import get_settings
from app.models.common import utcnow
from app.models.enums import SourceKind
from app.rag.documents import Chunk, KbStatus

BATCH_SIZE = 500
_TECHNIQUE_SEPARATOR = "|"

_clients: dict[str, Any] = {}
_chunk_cache: dict[tuple[str, str, str], list[Chunk]] = {}
_lock = threading.RLock()


def _client(path: str) -> Any:
    """Return the Chroma client for a folder, creating it once per process.

    Requests reach the store from worker threads, so creation is guarded by a lock.
    """
    with _lock:
        if path not in _clients:
            _clients[path] = chromadb.PersistentClient(
                path=path, settings=ChromaSettings(anonymized_telemetry=False)
            )
        return _clients[path]


def _to_metadata(chunk: Chunk) -> dict[str, Any]:
    """Flatten a chunk's metadata to the scalar values Chroma stores."""
    return {
        "document_id": chunk.document_id,
        "chunk_index": chunk.chunk_index,
        "source_name": chunk.source_name,
        "source_url": chunk.source_url,
        "section_id": chunk.section_id,
        "kind": chunk.kind.value,
        "control_family": chunk.control_family or "",
        "technique_ids": _TECHNIQUE_SEPARATOR.join(chunk.technique_ids),
    }


def _from_metadata(chunk_id: str, text: str, metadata: dict[str, Any]) -> Chunk:
    techniques = str(metadata.get("technique_ids", ""))
    return Chunk(
        id=chunk_id,
        text=text,
        document_id=str(metadata["document_id"]),
        chunk_index=int(metadata["chunk_index"]),
        source_name=str(metadata["source_name"]),
        source_url=str(metadata["source_url"]),
        section_id=str(metadata["section_id"]),
        kind=SourceKind(metadata["kind"]),
        control_family=str(metadata.get("control_family") or "") or None,
        technique_ids=[item for item in techniques.split(_TECHNIQUE_SEPARATOR) if item],
    )


class KnowledgeStore:
    """The knowledge base collection of one Chroma folder."""

    def __init__(self, path: str | None = None, collection: str | None = None) -> None:
        settings = get_settings()
        self.path = path or settings.chroma_path
        self.collection_name = collection or settings.kb_collection

    def _collection(self) -> Any | None:
        """Return the collection, or None when the index has not been built."""
        try:
            return _client(self.path).get_collection(self.collection_name)
        except (NotFoundError, ValueError):
            return None

    def replace_all(
        self, chunks: Sequence[Chunk], embeddings: Sequence[Sequence[float]], embedding_model: str
    ) -> datetime:
        """Drop the collection and write the given chunks. Returns the ingest time.

        Replacing the whole collection makes ingest idempotent: running it twice
        leaves the same chunks, never duplicates.
        """
        client = _client(self.path)
        if self._collection() is not None:
            client.delete_collection(self.collection_name)
        ingested_at = utcnow()
        collection = client.create_collection(
            self.collection_name,
            metadata={
                "hnsw:space": "cosine",
                "embedding_model": embedding_model,
                "ingested_at": ingested_at.isoformat(),
            },
        )
        for start in range(0, len(chunks), BATCH_SIZE):
            batch = chunks[start : start + BATCH_SIZE]
            collection.add(
                ids=[chunk.id for chunk in batch],
                documents=[chunk.text for chunk in batch],
                metadatas=[_to_metadata(chunk) for chunk in batch],
                embeddings=[list(vector) for vector in embeddings[start : start + BATCH_SIZE]],
            )
        _chunk_cache.clear()
        return ingested_at

    def all_chunks(self) -> list[Chunk]:
        """Return every stored chunk. Cached until the next ingest."""
        collection = self._collection()
        if collection is None:
            return []
        stamp = str((collection.metadata or {}).get("ingested_at", ""))
        key = (self.path, self.collection_name, stamp)
        with _lock:
            if key not in _chunk_cache:
                stored = collection.get(include=["documents", "metadatas"])
                _chunk_cache[key] = [
                    _from_metadata(chunk_id, text, metadata)
                    for chunk_id, text, metadata in zip(
                        stored["ids"], stored["documents"], stored["metadatas"]
                    )
                ]
            return _chunk_cache[key]

    def vector_search(
        self, embedding: Sequence[float], limit: int, kinds: Sequence[SourceKind] | None = None
    ) -> list[str]:
        """Return the ids of the nearest chunks, nearest first, optionally limited to some kinds."""
        collection = self._collection()
        if collection is None or collection.count() == 0:
            return []
        where = {"kind": {"$in": [kind.value for kind in kinds]}} if kinds else None
        result = collection.query(
            query_embeddings=[list(embedding)],
            n_results=min(limit, collection.count()),
            where=where,
            include=[],
        )
        return list(result["ids"][0])

    def status(self) -> KbStatus:
        """Return chunk counts per source and kind, the embedding model and the last ingest time."""
        collection = self._collection()
        if collection is None:
            return KbStatus(ready=False, collection=self.collection_name)
        chunks = self.all_chunks()
        metadata = collection.metadata or {}
        stamp = metadata.get("ingested_at")
        return KbStatus(
            ready=bool(chunks),
            collection=self.collection_name,
            total_chunks=len(chunks),
            chunks_by_source=dict(sorted(Counter(chunk.source_name for chunk in chunks).items())),
            chunks_by_kind=dict(sorted(Counter(chunk.kind.value for chunk in chunks).items())),
            embedding_model=metadata.get("embedding_model"),
            last_ingest_at=datetime.fromisoformat(stamp) if stamp else None,
        )
