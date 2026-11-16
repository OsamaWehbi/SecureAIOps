"""HTTP-layer security controls: API-key auth, rate limiting, security headers."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import uuid
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import Settings, get_settings
from app.core.logging import request_id_ctx

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(
    api_key: str | None = Depends(_api_key_header),
    settings: Settings = Depends(get_settings),
) -> str:
    """Validate the ``X-API-Key`` header in constant time.

    Returns a stable, non-reversible principal id used for audit + rate limits.
    When no keys are configured (local development) access is anonymous.
    """
    keys = settings.api_key_set
    if not keys:
        return "anonymous"
    if not api_key or not any(hmac.compare_digest(api_key, k) for k in keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "APIKey"},
        )
    return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:12]


class SlidingWindowRateLimiter:
    """In-process sliding-window limiter.

    Adequate for a single replica; swap for Redis (e.g. ``limits`` library)
    when running horizontally scaled.
    """

    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                retry_after = int(self.window - (now - q[0])) + 1
                return False, retry_after
            q.append(now)
            return True, 0


_limiter: SlidingWindowRateLimiter | None = None


def rate_limit(
    request: Request,
    principal: str = Depends(require_api_key),
    settings: Settings = Depends(get_settings),
) -> str:
    global _limiter
    if _limiter is None or _limiter.limit != settings.rate_limit_per_minute:
        _limiter = SlidingWindowRateLimiter(settings.rate_limit_per_minute)
    client = request.client.host if request.client else "unknown"
    allowed, retry_after = _limiter.check(f"{principal}|{client}")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
    return principal


CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds OWASP-recommended response headers and a correlation id."""

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        # Never trust arbitrary client ids: bound length + charset.
        rid = "".join(c for c in rid if c.isalnum() or c in "-_")[:64] or uuid.uuid4().hex[:16]
        token = request_id_ctx.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)

        h = response.headers
        h["X-Request-ID"] = rid
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        path = request.url.path
        if path.startswith(("/docs", "/redoc")):
            # Swagger UI loads its bundle from a CDN; relax CSP only there.
            pass
        else:
            h["Content-Security-Policy"] = CSP
        if path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
