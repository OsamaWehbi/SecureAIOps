"""Embed the markdown knowledge base into PostgreSQL/pgvector.

Idempotent: chunks are upserted by stable id, so re-running after editing a
policy only refreshes changed content.

    python scripts/ingest_knowledge.py            # uses DATABASE_URL / DB_* from .env
    python scripts/ingest_knowledge.py --dry-run  # show chunks without embedding
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.rag.knowledge import load_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    chunks = load_corpus(settings.kb_path)
    print(f"[*] {len(chunks)} chunks from {settings.kb_path}")
    if args.dry_run:
        for c in chunks:
            print(f"    {c.id:<40} {c.title} › {c.section}")
        return 0

    if not settings.sqlalchemy_url.startswith("postgresql"):
        print("[!] pgvector ingestion requires a PostgreSQL DATABASE_URL", file=sys.stderr)
        return 1
    if settings.resolved_llm_provider != "gemini":
        print("[!] GEMINI_API_KEY is required to compute embeddings", file=sys.stderr)
        return 1

    from langchain_google_genai import GoogleGenerativeAIEmbeddings

    from app.db.models import EMBEDDING_DIM, KnowledgeChunk
    from app.db.session import SessionLocal, init_db

    init_db()
    embedder = GoogleGenerativeAIEmbeddings(
        model=settings.gemini_embedding_model, google_api_key=settings.gemini_api_key.get_secret_value()
    )
    texts = [f"{c.title}\n{c.section}\n{c.text}" for c in chunks]
    vectors = embedder.embed_documents(
        texts, task_type="RETRIEVAL_DOCUMENT", titles=[c.title for c in chunks], output_dimensionality=EMBEDDING_DIM
    )
    with SessionLocal() as db:
        for c, v in zip(chunks, vectors, strict=True):
            db.merge(
                KnowledgeChunk(
                    id=c.id,
                    source=c.source,
                    title=c.title,
                    section=c.section,
                    content=c.text,
                    embedding=list(v)[:EMBEDDING_DIM],
                )
            )
        db.commit()
    print(f"[+] Upserted {len(chunks)} chunks into knowledge_chunks. Set KB_BACKEND=pgvector to use them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
