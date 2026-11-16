"""Centralised, validated runtime configuration.

All settings are read from environment variables (or a local ``.env`` file) and
validated by pydantic. Secrets are wrapped in ``SecretStr`` so they never leak
into logs, tracebacks or ``repr()`` output.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application -------------------------------------------------------
    project_name: str = "SecureAIOps"
    app_env: Literal["development", "production", "test"] = "development"
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"
    log_json: bool = False

    # --- LLM provider ------------------------------------------------------
    # "auto" -> Gemini when a key is configured, otherwise the deterministic
    # offline engine (useful for demos, CI and air-gapped environments).
    llm_provider: Literal["auto", "gemini", "offline"] = "auto"
    gemini_api_key: SecretStr | None = None
    gemini_model: str = "gemini-3.1-flash-lite"
    gemini_embedding_model: str = "models/gemini-embedding-2"
    llm_temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    llm_timeout_seconds: int = Field(default=45, ge=5, le=300)

    # --- Persistence -------------------------------------------------------
    database_url: str | None = None
    db_user: str | None = None
    db_password: SecretStr | None = None
    db_host: str | None = None
    db_port: int = 5432
    db_name: str = "secureaiops"

    # --- Retrieval (RAG) ---------------------------------------------------
    kb_backend: Literal["local", "pgvector"] = "local"
    kb_path: Path = PROJECT_ROOT / "knowledge_base"
    kb_top_k: int = Field(default=3, ge=1, le=10)

    # --- API security ------------------------------------------------------
    # Comma-separated list of accepted API keys. Empty -> auth disabled
    # (allowed only outside production; see ``validate_production``).
    api_keys: str = ""
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    rate_limit_per_minute: int = Field(default=30, ge=1)
    max_input_chars: int = Field(default=12_000, ge=100, le=200_000)

    # --- Guardrails --------------------------------------------------------
    guard_block_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    guard_use_llm: bool = True

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    # ------------------------------------------------------------------ derived
    @property
    def resolved_llm_provider(self) -> Literal["gemini", "offline"]:
        if self.llm_provider == "auto":
            key = self.gemini_api_key.get_secret_value() if self.gemini_api_key else ""
            return "gemini" if key.strip() else "offline"
        return self.llm_provider

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        if self.db_host and self.db_user:
            pwd = self.db_password.get_secret_value() if self.db_password else ""
            return f"postgresql+psycopg2://{self.db_user}:{pwd}@{self.db_host}:{self.db_port}/{self.db_name}"
        (PROJECT_ROOT / "data").mkdir(exist_ok=True)
        return f"sqlite:///{(PROJECT_ROOT / 'data' / 'secureaiops.db').as_posix()}"

    @property
    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def validate_production(self) -> None:
        """Fail fast on insecure production configuration."""
        if self.app_env != "production":
            return
        problems = []
        if not self.api_key_set:
            problems.append("API_KEYS must be set in production")
        if "*" in self.cors_origin_list:
            problems.append("CORS_ORIGINS must not contain '*' in production")
        if self.sqlalchemy_url.startswith("sqlite"):
            problems.append("a PostgreSQL DATABASE_URL is required in production")
        if problems:
            raise RuntimeError("Insecure production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
