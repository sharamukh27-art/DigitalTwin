"""Hybrid retrieval: metadata prefilter + BM25, vector search, reciprocal rank fusion."""

from collections.abc import Sequence

from rank_bm25 import BM25Okapi

from app.models.enums import SourceKind
from app.rag.documents import Chunk, RetrievedChunk
from app.rag.embedding import Embedder, get_embedder, tokenize
from app.rag.store import KnowledgeStore

RRF_K = 60
CANDIDATES = 30
DEFENSIVE_KINDS: tuple[SourceKind, ...] = (SourceKind.D3FEND, SourceKind.NIST)


def bm25_rank(query: str, chunks: Sequence[Chunk]) -> list[str]:
    """Return chunk ids ordered by BM25 score for the query, best first."""
    if not chunks:
        return []
    scores = BM25Okapi([tokenize(chunk.text) for chunk in chunks]).get_scores(tokenize(query))
    order = sorted(range(len(chunks)), key=lambda index: (-scores[index], chunks[index].id))
    return [chunks[index].id for index in order]


def reciprocal_rank_fusion(rankings: Sequence[Sequence[str]], k: int = RRF_K) -> dict[str, float]:
    """Fuse ranked id lists: each id scores the sum of 1 / (k + rank) over the lists it is in."""
    fused: dict[str, float] = {}
    for ranking in rankings:
        for rank, item in enumerate(ranking, start=1):
            fused[item] = fused.get(item, 0.0) + 1.0 / (k + rank)
    return fused


def _to_result(chunk: Chunk, score: float) -> RetrievedChunk:
    return RetrievedChunk(
        text=chunk.text,
        source_name=chunk.source_name,
        source_url=chunk.source_url,
        section_id=chunk.section_id,
        score=round(score, 6),
        kind=chunk.kind,
        technique_ids=chunk.technique_ids,
    )


def retrieve(
    query: str,
    technique_ids: Sequence[str],
    k: int = 6,
    store: KnowledgeStore | None = None,
    embedder: Embedder | None = None,
) -> list[RetrievedChunk]:
    """Return the k best chunks for a query about some ATT&CK techniques.

    (a) Prefilter to chunks whose technique_ids intersect the given techniques: the
        techniques' own ATT&CK entries (with their mitigations) and the defenses
        mapped to them.
    (b) Rank that subset with BM25.
    (c) Rank the whole collection by vector similarity.
    (d) Merge both rankings with reciprocal rank fusion, keep the best chunk per
        section_id, and take the top k.

    Two guarantees are then applied when the index allows: the result holds the
    ATT&CK entry of the first technique given, and at least one D3FEND or NIST chunk.
    They replace the lowest-ranked results. An empty or missing index returns [].
    """
    store = store or KnowledgeStore()
    chunks = {chunk.id: chunk for chunk in store.all_chunks()}
    if not chunks or k < 1:
        return []
    embedder = embedder or get_embedder()
    wanted = set(technique_ids)
    query_vector = embedder.embed([query])[0]

    subset = [chunk for chunk in chunks.values() if wanted & set(chunk.technique_ids)]
    keyword_ranking = bm25_rank(query, subset)[:CANDIDATES]
    vector_ranking = store.vector_search(query_vector, CANDIDATES)
    fused = reciprocal_rank_fusion([keyword_ranking, vector_ranking])

    ordered = sorted(fused, key=lambda chunk_id: (-fused[chunk_id], chunk_id))
    best: list[str] = []
    seen_sections: set[str] = set()
    for chunk_id in ordered:
        section = chunks[chunk_id].section_id
        if chunk_id in chunks and section not in seen_sections:
            seen_sections.add(section)
            best.append(chunk_id)
    selected = best[:k]

    def force_in(candidate_id: str | None) -> None:
        """Put a chunk into the selection, replacing the lowest-ranked non-pinned one."""
        if candidate_id is None or candidate_id in selected:
            return
        if len(selected) >= k:
            removable = [item for item in reversed(selected) if item not in pinned]
            if not removable:
                return
            selected.remove(removable[0])
        selected.append(candidate_id)
        pinned.add(candidate_id)

    pinned: set[str] = set()
    primary = technique_ids[0] if technique_ids else None
    if primary is not None:
        own = sorted(
            (c for c in chunks.values() if c.kind == SourceKind.ATTACK and c.section_id == primary),
            key=lambda chunk: chunk.chunk_index,
        )
        if own and not any(chunks[item].section_id == primary for item in selected):
            force_in(own[0].id)
        pinned.update(item for item in selected if chunks[item].section_id == primary)

    if not any(chunks[item].kind in DEFENSIVE_KINDS for item in selected):
        defensive = next((item for item in best if chunks[item].kind in DEFENSIVE_KINDS), None)
        if defensive is None:
            nearest = store.vector_search(query_vector, 1, kinds=DEFENSIVE_KINDS)
            defensive = nearest[0] if nearest else None
        force_in(defensive)

    results = [_to_result(chunks[item], fused.get(item, 0.0)) for item in selected]
    return sorted(results, key=lambda result: (-result.score, result.section_id))
