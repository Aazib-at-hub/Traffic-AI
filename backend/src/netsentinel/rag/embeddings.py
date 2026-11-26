"""BGE Embedding & Cross-Encoder Reranker wrappers with deterministic lightweight fallback."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from netsentinel.core.config import get_settings

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-\.]+")
_EMBEDDER_INSTANCE: Any = None
_RERANKER_INSTANCE: Any = None


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text)]


def _hash_embed(text: str, dim: int = 128) -> list[float]:
    """Deterministic bag-of-tokens + char-trigram hashed unit vector for zero-download dev/tests."""
    vec = [0.0] * dim
    tokens = tokenize(text)
    if not tokens:
        return vec
    for tok in tokens:
        h = int(hashlib.blake2b(tok.encode("utf-8"), digest_size=8).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [round(x / norm, 6) for x in vec]


def embed_texts(texts: list[str]) -> list[list[float]]:
    global _EMBEDDER_INSTANCE
    settings = get_settings()
    if settings.use_local_hash_embedder:
        return [_hash_embed(t, dim=128) for t in texts]
    try:
        if _EMBEDDER_INSTANCE is None:
            from sentence_transformers import SentenceTransformer

            _EMBEDDER_INSTANCE = SentenceTransformer(settings.embedding_model)
        embs = _EMBEDDER_INSTANCE.encode(texts, normalize_embeddings=True)
        return [e.tolist() for e in embs]
    except Exception:
        return [_hash_embed(t, dim=128) for t in texts]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


def rerank_pairs(query: str, passages: list[str]) -> list[float]:
    """Score (query, passage) pairs using BGE cross-encoder or deterministic lexical-overlap fallback."""
    global _RERANKER_INSTANCE
    settings = get_settings()
    if not passages:
        return []
    if not settings.use_local_hash_embedder:
        try:
            if _RERANKER_INSTANCE is None:
                from sentence_transformers import CrossEncoder

                _RERANKER_INSTANCE = CrossEncoder(settings.reranker_model)
            scores = _RERANKER_INSTANCE.predict([(query, p) for p in passages])
            return [round(float(s), 6) for s in scores]
        except Exception:
            pass

    q_tokens = set(tokenize(query))
    out: list[float] = []
    for passage in passages:
        p_tokens = tokenize(passage)
        if not q_tokens or not p_tokens:
            out.append(0.0)
            continue
        p_set = set(p_tokens)
        overlap = len(q_tokens & p_set) / len(q_tokens)
        # Boost exact uppercase security IDs like T1046 or CVE-2024-...
        exact_bonus = sum(0.25 for t in q_tokens if (t.startswith("t1") or t.startswith("cve-")) and t in p_set)
        out.append(round(min(overlap + exact_bonus, 1.0), 6))
    return out
