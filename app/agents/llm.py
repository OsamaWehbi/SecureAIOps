"""LLM provider abstraction.

Every LLM call in the platform goes through ``structured_call`` which:
  * requests schema-constrained (JSON) output — no brittle string parsing,
  * enforces a timeout and bounded retries,
  * raises ``LLMUnavailable`` so callers can degrade to deterministic logic.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import TypeVar

from pydantic import BaseModel

from app.core.config import get_settings

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class LLMUnavailable(RuntimeError):
    pass


def live() -> bool:
    return get_settings().resolved_llm_provider == "gemini"


def engine_label() -> str:
    s = get_settings()
    return f"gemini:{s.gemini_model}" if live() else "offline-deterministic"


@lru_cache
def _chat_model():
    from langchain_google_genai import ChatGoogleGenerativeAI

    s = get_settings()
    return ChatGoogleGenerativeAI(
        model=s.gemini_model,
        google_api_key=s.gemini_api_key.get_secret_value() if s.gemini_api_key else None,
        temperature=s.llm_temperature,
        timeout=s.llm_timeout_seconds,
        max_retries=2,
    )


def structured_call(schema: type[T], system: str, user: str) -> T:
    if not live():
        raise LLMUnavailable("offline mode")
    from langchain_core.messages import HumanMessage, SystemMessage

    try:
        runnable = _chat_model().with_structured_output(schema)
        result = runnable.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    except Exception as exc:
        log.warning("LLM call failed (%s): %s", schema.__name__, type(exc).__name__)
        raise LLMUnavailable(str(exc)) from exc
    if result is None:
        raise LLMUnavailable("empty structured response")
    return result
