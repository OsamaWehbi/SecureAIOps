"""Data-access helpers for incidents."""

from __future__ import annotations

import hashlib

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Incident


def save_incident(db: Session, *, session_id: str, principal: str, payload: str, result: dict) -> Incident:
    # Persist guardrail verdicts with the report so audit replays are exact.
    report = {
        **result.get("report", {}),
        "guardrails": {"input": result.get("guard", {}), "output": result.get("output_guard", {})},
    }
    incident = Incident(
        session_id=session_id,
        principal=principal,
        payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
        payload=payload,
        route=result.get("route", "blocked"),
        blocked=result.get("blocked", False),
        severity=report.get("severity", "INFO"),
        risk_score=report.get("risk", {}).get("score", 0),
        guard_score=result.get("guard", {}).get("risk_score", 0.0),
        engine=result.get("engine", "offline"),
        latency_ms=result.get("latency_ms", 0),
        title=report.get("title", "")[:200],
        report=report,
        trace=result.get("trace", []),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def list_incidents(db: Session, limit: int = 50, offset: int = 0) -> list[Incident]:
    stmt = select(Incident).order_by(Incident.id.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt))


def get_incident(db: Session, incident_id: int) -> Incident | None:
    return db.get(Incident, incident_id)


def record_decision(db: Session, incident: Incident, action_index: int, decision: str, principal: str) -> Incident:
    decisions = dict(incident.decisions or {})
    decisions[str(action_index)] = {"decision": decision, "by": principal}
    incident.decisions = decisions
    db.commit()
    db.refresh(incident)
    return incident


def stats(db: Session) -> dict:
    total = db.scalar(select(func.count(Incident.id))) or 0
    blocked = db.scalar(select(func.count(Incident.id)).where(Incident.blocked.is_(True))) or 0
    high = db.scalar(select(func.count(Incident.id)).where(Incident.severity.in_(["HIGH", "CRITICAL"]))) or 0
    avg_latency = db.scalar(select(func.avg(Incident.latency_ms))) or 0
    by_sev = dict(db.execute(select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)).all())
    by_route = dict(db.execute(select(Incident.route, func.count(Incident.id)).group_by(Incident.route)).all())
    return {
        "total": total,
        "blocked": blocked,
        "high_or_critical": high,
        "avg_latency_ms": round(float(avg_latency)),
        "by_severity": by_sev,
        "by_route": by_route,
    }
