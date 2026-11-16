"""Platform metadata and knowledge-base endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app import __version__
from app.agents.llm import engine_label
from app.core.config import Settings, get_settings
from app.core.security import require_api_key
from app.guardrails.input_guard import RULES
from app.intel.mitre_catalog import TECHNIQUES
from app.rag.knowledge import get_knowledge_base

router = APIRouter(tags=["Platform"])


@router.get("/meta", summary="Public, non-sensitive platform capabilities")
def meta(settings: Settings = Depends(get_settings)):
    kb = get_knowledge_base()
    return {
        "name": settings.project_name,
        "version": __version__,
        "environment": settings.app_env,
        "engine": engine_label(),
        "auth_required": bool(settings.api_key_set),
        "knowledge_backend": kb.backend,
        "guard_rules": len(RULES),
        "attack_techniques": len(TECHNIQUES),
        "max_input_chars": settings.max_input_chars,
    }


@router.get("/knowledge")
def knowledge_documents(_: str = Depends(require_api_key)):
    return get_knowledge_base().documents()


@router.get("/knowledge/search")
def knowledge_search(
    q: str = Query(..., min_length=2, max_length=500), k: int = Query(5, ge=1, le=10), _: str = Depends(require_api_key)
):
    return [h.to_dict() for h in get_knowledge_base().search(q, k)]
