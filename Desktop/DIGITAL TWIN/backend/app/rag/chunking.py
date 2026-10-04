"""Chunking: split long documents into overlapping pieces that keep their metadata."""

from app.rag.documents import Chunk, Document

TOKENS_PER_WORD = 4 / 3


def estimate_tokens(text: str) -> int:
    """Estimate the token count of a text from its word count (about 4 tokens per 3 words)."""
    return round(len(text.split()) * TOKENS_PER_WORD)


def chunk_document(document: Document, max_tokens: int, overlap_tokens: int) -> list[Chunk]:
    """Split a document into chunks of at most about `max_tokens`, overlapping by `overlap_tokens`.

    A document that fits stays one chunk. Every chunk carries the document's metadata.
    """
    if max_tokens <= overlap_tokens:
        raise ValueError("max_tokens must be larger than overlap_tokens")

    def make(index: int, text: str) -> Chunk:
        return Chunk(
            **document.model_dump(exclude={"id", "text"}),
            id=f"{document.id}::{index}",
            text=text,
            document_id=document.id,
            chunk_index=index,
        )

    if estimate_tokens(document.text) <= max_tokens:
        return [make(0, document.text)]

    words = document.text.split()
    size = max(1, int(max_tokens / TOKENS_PER_WORD))
    step = max(1, size - int(overlap_tokens / TOKENS_PER_WORD))
    chunks: list[Chunk] = []
    for start in range(0, len(words), step):
        chunks.append(make(len(chunks), " ".join(words[start : start + size])))
        if start + size >= len(words):
            break
    return chunks


def chunk_documents(documents: list[Document], max_tokens: int, overlap_tokens: int) -> list[Chunk]:
    """Chunk every document, in order."""
    chunks: list[Chunk] = []
    for document in documents:
        chunks.extend(chunk_document(document, max_tokens, overlap_tokens))
    return chunks
