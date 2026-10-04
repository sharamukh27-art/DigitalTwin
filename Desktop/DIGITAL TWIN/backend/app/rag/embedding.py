"""Embedders: the sentence-transformers model, and a small deterministic one for tests."""

import hashlib
import math
import re
import threading
from collections.abc import Sequence
from typing import Protocol

from app.core.config import get_settings

_WORD = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")


def tokenize(text: str) -> list[str]:
    """Lower-case a text and split it into word tokens. Technique ids like t1557.002 stay whole."""
    return _WORD.findall(text.lower())


class Embedder(Protocol):
    """Turns texts into vectors."""

    name: str

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one unit-length vector per text."""
        ...


class SentenceTransformerEmbedder:
    """Embeds with a sentence-transformers model. The model loads on first use."""

    def __init__(self, model_name: str) -> None:
        self.name = model_name
        self._model: object | None = None
        self._lock = threading.Lock()

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        with self._lock:
            if self._model is None:
                from sentence_transformers import SentenceTransformer

                self._model = SentenceTransformer(self.name)
        vectors = self._model.encode(  # type: ignore[attr-defined]
            list(texts), normalize_embeddings=True, show_progress_bar=False, batch_size=64
        )
        return [[float(value) for value in vector] for vector in vectors]


class HashEmbedder:
    """Deterministic bag-of-words embedder. Needs no model download; used by tests."""

    def __init__(self, dimensions: int = 256) -> None:
        self.name = f"hash-bow-{dimensions}"
        self.dimensions = dimensions

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vector = [0.0] * self.dimensions
            for token in tokenize(text):
                digest = hashlib.md5(token.encode("utf-8")).digest()  # noqa: S324 - not security
                vector[int.from_bytes(digest[:4], "big") % self.dimensions] += 1.0
            norm = math.sqrt(sum(value * value for value in vector)) or 1.0
            vectors.append([value / norm for value in vector])
        return vectors


_embedder: Embedder | None = None


def get_embedder() -> Embedder:
    """Return the active embedder, creating the configured model on first use."""
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformerEmbedder(get_settings().embedding_model)
    return _embedder


def set_embedder(embedder: Embedder | None) -> None:
    """Replace the active embedder. Used by tests; None restores the configured model."""
    global _embedder
    _embedder = embedder
