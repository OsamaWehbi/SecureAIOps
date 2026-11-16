"""ORM models: immutable incident audit trail + vector knowledge store."""

from __future__ import annotations

import datetime as dt

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

EMBEDDING_DIM = 768


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class Incident(Base):
    """One analysed request. Rows are append-only (analyst decisions are the
    only mutable field) so the table doubles as an AI decision audit log."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    principal: Mapped[str] = mapped_column(String(64), default="anonymous")
    payload_sha256: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[str] = mapped_column(Text)
    route: Mapped[str] = mapped_column(String(40), default="blocked")
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    guard_score: Mapped[float] = mapped_column(Float, default=0.0)
    engine: Mapped[str] = mapped_column(String(40), default="offline")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(200), default="")
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    trace: Mapped[list] = mapped_column(JSON, default=list)
    decisions: Mapped[dict] = mapped_column(JSON, default=dict)


class KnowledgeChunk(Base):
    """Embedded knowledge passages for dense retrieval (PostgreSQL only)."""

    __tablename__ = "knowledge_chunks"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    source: Mapped[str] = mapped_column(String(200), index=True)
    title: Mapped[str] = mapped_column(String(255))
    section: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)
    embedding = mapped_column(Vector(EMBEDDING_DIM), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
