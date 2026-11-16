"""SecureAIOps — FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.agents.llm import engine_label
from app.api.v1.routes import analyze, incidents, system
from app.core.config import PROJECT_ROOT, get_settings
from app.core.logging import configure_logging
from app.core.security import SecurityHeadersMiddleware
from app.db.session import db_healthy, init_db

STATIC_DIR = PROJECT_ROOT / "app" / "static"
log = logging.getLogger("secureaiops")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    settings.validate_production()
    init_db()
    if not settings.api_key_set:
        log.warning("API authentication is DISABLED (no API_KEYS configured) — development only")
    log.info("SecureAIOps %s started · engine=%s · env=%s", __version__, engine_label(), settings.app_env)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SecureAIOps API",
        version=__version__,
        description="Agentic SOC copilot: guarded multi-agent triage, ATT&CK mapping and policy-grounded RAG.",
        lifespan=lifespan,
        docs_url="/docs" if settings.app_env != "production" else None,
        redoc_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
    )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Return field-level errors without echoing the (possibly hostile) input back.
        errors = [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    prefix = settings.api_v1_prefix
    app.include_router(analyze.router, prefix=prefix)
    app.include_router(incidents.router, prefix=prefix)
    app.include_router(system.router, prefix=prefix)

    @app.get("/health", tags=["Infrastructure"], summary="Liveness probe")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/ready", tags=["Infrastructure"], summary="Readiness probe")
    def ready():
        ok = db_healthy()
        return JSONResponse(
            status_code=status.HTTP_200_OK if ok else status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "ready" if ok else "degraded", "database": ok, "engine": engine_label()},
        )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
