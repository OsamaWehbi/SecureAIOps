"""Test configuration: hermetic, offline, no external services."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Must be set before any `app` import so cached settings pick them up.
_tmp = Path(tempfile.mkdtemp(prefix="secureaiops-test-"))
os.environ.update(
    {
        "APP_ENV": "test",
        "LLM_PROVIDER": "offline",
        "GEMINI_API_KEY": "",
        "DATABASE_URL": f"sqlite:///{(_tmp / 'test.db').as_posix()}",
        "KB_BACKEND": "local",
        "API_KEYS": "",
        "RATE_LIMIT_PER_MINUTE": "1000",
        "DB_HOST": "",
        "DB_USER": "",
    }
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    from app.main import app

    with TestClient(app) as c:
        yield c
