"""Knowledge base models: documents, chunks, retrieval results and index status."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import SourceKind


class Document(BaseModel):
    """One normalised knowledge base entry, before chunking."""

    id: str
    text: str
    source_name: str
    source_url: str
    section_id: str
    technique_ids: list[str] = Field(default_factory=list)
    control_family: str | None = None
    kind: SourceKind


class Chunk(Document):
    """A piece of a document small enough to embed. Keeps the document's metadata."""

    document_id: str
    chunk_index: int


class RetrievedChunk(BaseModel):
    """A chunk returned by retrieval, with its fused rank score."""

    text: str
    source_name: str
    source_url: str
    section_id: str
    score: float
    kind: SourceKind
    technique_ids: list[str] = Field(default_factory=list)


class IngestSummary(BaseModel):
    """Result of building the index."""

    documents_by_source: dict[str, int]
    chunks_by_source: dict[str, int]
    total_chunks: int
    skipped_sources: list[str]
    embedding_model: str
    ingested_at: datetime


class KbStatus(BaseModel):
    """State of the knowledge base index."""

    ready: bool
    collection: str
    total_chunks: int = 0
    chunks_by_source: dict[str, int] = Field(default_factory=dict)
    chunks_by_kind: dict[str, int] = Field(default_factory=dict)
    embedding_model: str | None = None
    last_ingest_at: datetime | None = None
