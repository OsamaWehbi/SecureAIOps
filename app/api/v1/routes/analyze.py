"""Analysis endpoints (sync JSON + Server-Sent Events streaming)."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.agents.service import analyze, analyze_stream
from app.api.v1.schemas import AnalyzeRequest, AnalyzeResponse
from app.core.security import rate_limit
from app.db.repository import save_incident
from app.db.session import SessionLocal, get_db

router = APIRouter(tags=["Analysis"])
log = logging.getLogger(__name__)


@router.post("/analyze", response_model=AnalyzeResponse, summary="Run the multi-agent triage pipeline")
def analyze_endpoint(
    body: AnalyzeRequest, db: Session = Depends(get_db), principal: str = Depends(rate_limit)
) -> AnalyzeResponse:
    try:
        result = analyze(body.message, body.session_id)
    except Exception:
        log.exception("analysis pipeline failed")
        # Never leak internals (stack traces, provider errors) to clients.
        raise HTTPException(status_code=500, detail="Analysis pipeline failed; see server logs") from None
    incident = save_incident(db, session_id=body.session_id, principal=principal, payload=body.message, result=result)
    return AnalyzeResponse(incident_id=incident.id, **result)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@router.post("/analyze/stream", summary="Stream agent steps as Server-Sent Events")
def analyze_stream_endpoint(body: AnalyzeRequest, principal: str = Depends(rate_limit)) -> StreamingResponse:
    def events():
        try:
            for kind, payload in analyze_stream(body.message, body.session_id):
                if kind == "result":
                    with SessionLocal() as db:
                        incident = save_incident(
                            db, session_id=body.session_id, principal=principal, payload=body.message, result=payload
                        )
                    payload = {"incident_id": incident.id, **payload}
                yield _sse(kind, payload)
        except Exception:
            log.exception("streaming pipeline failed")
            yield _sse("error", {"detail": "Analysis pipeline failed; see server logs"})

    return StreamingResponse(
        events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"}
    )
