"""Incident audit trail and human-in-the-loop decisions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.v1.schemas import DecisionRequest, IncidentDetail, IncidentSummary
from app.core.security import require_api_key
from app.db import repository
from app.db.session import get_db

router = APIRouter(tags=["Incidents"])


@router.get("/incidents", response_model=list[IncidentSummary])
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: str = Depends(require_api_key),
):
    return repository.list_incidents(db, limit, offset)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db), _: str = Depends(require_api_key)):
    incident = repository.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@router.post(
    "/incidents/{incident_id}/decisions",
    response_model=IncidentDetail,
    summary="Approve or reject a recommended response action (human-in-the-loop)",
)
def decide(
    incident_id: int,
    body: DecisionRequest,
    db: Session = Depends(get_db),
    principal: str = Depends(require_api_key),
):
    incident = repository.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    actions = (incident.report or {}).get("actions", [])
    if body.action_index >= len(actions):
        raise HTTPException(422, "action_index out of range")
    if not actions[body.action_index].get("requires_approval"):
        raise HTTPException(409, "Action does not require approval")
    return repository.record_decision(db, incident, body.action_index, body.decision, principal)


@router.get("/stats")
def get_stats(db: Session = Depends(get_db), _: str = Depends(require_api_key)):
    return repository.stats(db)
