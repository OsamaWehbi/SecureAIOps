"""Retrieval-Augmented Generation knowledge base.

Two interchangeable backends behind one interface:

* ``LocalKnowledgeBase`` — Okapi BM25 over the markdown corpus in
  ``knowledge_base/``. Zero dependencies, deterministic, works offline.
* ``PgVectorKnowledgeBase`` — dense retrieval with Gemini embeddings stored in
  PostgreSQL/pgvector (cosine distance, HNSW-ready). Falls back to BM25 if
  the vector store is unavailable, so retrieval degrades instead of failing.

Retrieved passages are *untrusted data*: they are spotlighted before being
placed in a prompt (indirect prompt injection via poisoned documents is a
real attack path).
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from app.core.config import get_settings

log = logging.getLogger(__name__)
_TOKEN = re.compile(r"[a-z0-9]+(?:[.\-/][a-z0-9]+)*")
_STOP = set(
    "a an and are as at be by for from has have how i in is it its of on or that the this to was "
    "were what when where which who will with do does can we our you your my me any all not".split()
)


@dataclass(frozen=True)
class Chunk:
    id: str
    source: str
    title: str
    section: str
    text: str


@dataclass(frozen=True)
class Hit:
    source: str
    title: str
    section: str
    text: str
    score: float

    def to_dict(self) -> dict:
        return asdict(self)


class KnowledgeBase(Protocol):
    backend: str

    def search(self, query: str, k: int = 3) -> list[Hit]: ...

    def documents(self) -> list[dict]: ...


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


def load_corpus(path: Path) -> list[Chunk]:
    """Chunk markdown files by H2/H3 headings, keeping the H1 as doc title."""
    chunks: list[Chunk] = []
    for file in sorted(path.glob("*.md")):
        raw = file.read_text(encoding="utf-8")
        title_match = re.search(r"^#\s+(.+)$", raw, re.M)
        title = title_match.group(1).strip() if title_match else file.stem
        parts = re.split(r"^(#{2,3}\s+.+)$", raw, flags=re.M)
        preamble = parts[0]
        body = re.sub(r"^#\s+.+$", "", preamble, flags=re.M).strip()
        if body:
            chunks.append(Chunk(f"{file.stem}#0", file.name, title, "Overview", body))
        for i in range(1, len(parts), 2):
            section = parts[i].lstrip("#").strip()
            text = parts[i + 1].strip() if i + 1 < len(parts) else ""
            if text:
                chunks.append(Chunk(f"{file.stem}#{i // 2 + 1}", file.name, title, section, text))
    return chunks


class LocalKnowledgeBase:
    backend = "bm25-local"

    def __init__(self, path: Path, k1: float = 1.5, b: float = 0.75) -> None:
        self.chunks = load_corpus(path)
        self.k1, self.b = k1, b
        self._docs = [tokenize(f"{c.title} {c.section} {c.section} {c.text}") for c in self.chunks]
        self._tf = [Counter(d) for d in self._docs]
        self._avgdl = sum(map(len, self._docs)) / max(1, len(self._docs))
        df: Counter[str] = Counter()
        for d in self._docs:
            df.update(set(d))
        n = len(self._docs)
        self._idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 3) -> list[Hit]:
        q = tokenize(query)
        if not q:
            return []
        scored: list[tuple[float, int]] = []
        for idx, tf in enumerate(self._tf):
            dl = len(self._docs[idx])
            s = 0.0
            for term in q:
                if term in tf:
                    f = tf[term]
                    s += self._idf[term] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self._avgdl))
            if s > 0:
                scored.append((s, idx))
        scored.sort(reverse=True)
        top = scored[:k]
        if not top:
            return []
        best = top[0][0]
        return [
            Hit(
                self.chunks[i].source,
                self.chunks[i].title,
                self.chunks[i].section,
                self.chunks[i].text,
                round(s / best, 3),
            )
            for s, i in top
            if s / best >= 0.25  # drop weak tail matches
        ]

    def documents(self) -> list[dict]:
        docs: dict[str, dict] = {}
        for c in self.chunks:
            d = docs.setdefault(c.source, {"source": c.source, "title": c.title, "sections": []})
            d["sections"].append(c.section)
        return list(docs.values())


class PgVectorKnowledgeBase:
    backend = "pgvector"

    def __init__(self, fallback: LocalKnowledgeBase) -> None:
        from langchain_google_genai import GoogleGenerativeAIEmbeddings

        s = get_settings()
        self.fallback = fallback
        self.embedder = GoogleGenerativeAIEmbeddings(
            model=s.gemini_embedding_model,
            google_api_key=s.gemini_api_key.get_secret_value() if s.gemini_api_key else None,
        )

    def embed(self, text: str) -> list[float]:
        from app.db.models import EMBEDDING_DIM

        vec = self.embedder.embed_query(text, task_type="RETRIEVAL_QUERY", output_dimensionality=EMBEDDING_DIM)
        return list(vec)[:EMBEDDING_DIM]

    def search(self, query: str, k: int = 3) -> list[Hit]:
        from app.db.models import KnowledgeChunk
        from app.db.session import SessionLocal

        try:
            vector = self.embed(query)
            with SessionLocal() as db:
                distance = KnowledgeChunk.embedding.cosine_distance(vector)
                rows = db.query(KnowledgeChunk, distance.label("d")).order_by(distance).limit(k).all()
            return [Hit(r.source, r.title, r.section, r.content, round(1 - d, 3)) for r, d in rows]
        except Exception:
            log.exception("pgvector search failed; falling back to BM25")
            return self.fallback.search(query, k)

    def documents(self) -> list[dict]:
        return self.fallback.documents()


@lru_cache
def get_knowledge_base() -> KnowledgeBase:
    s = get_settings()
    local = LocalKnowledgeBase(s.kb_path)
    if s.kb_backend == "pgvector":
        try:
            return PgVectorKnowledgeBase(local)
        except Exception:
            log.exception("pgvector backend unavailable; using local BM25")
    return local
