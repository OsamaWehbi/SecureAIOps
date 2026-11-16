"""Environment diagnostics — checks configuration without printing secrets.

python scripts/doctor.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

OK, WARN, FAIL = "\033[32m✔\033[0m", "\033[33m!\033[0m", "\033[31m✘\033[0m"


def main() -> int:
    from app.core.config import get_settings

    failures = 0
    s = get_settings()
    print("SecureAIOps doctor\n")

    py = sys.version_info
    print(f" {OK if py >= (3, 11) else FAIL} Python {py.major}.{py.minor}.{py.micro} (>= 3.11 required)")
    failures += py < (3, 11)

    provider = s.resolved_llm_provider
    print(
        f" {OK} Reasoning engine: {provider}" + (f" ({s.gemini_model})" if provider == "gemini" else " — offline mode")
    )

    url = s.sqlalchemy_url
    backend = url.split(":", 1)[0]
    try:
        from app.db.session import db_healthy

        healthy = db_healthy()
    except Exception as exc:  # noqa: BLE001
        healthy = False
        print(f"   {type(exc).__name__}")
    print(f" {OK if healthy else FAIL} Database reachable ({backend})")
    failures += not healthy

    if provider == "gemini":
        try:
            from app.agents.llm import _chat_model

            msg = _chat_model().invoke("Reply with exactly: ACK")
            reply = msg.text if isinstance(getattr(msg, "text", None), str) else msg.content
            print(f" {OK} Gemini reachable (reply: {str(reply)[:20]!r})")
        except Exception as exc:  # noqa: BLE001
            print(f" {FAIL} Gemini call failed: {type(exc).__name__}")
            failures += 1

    from app.rag.knowledge import get_knowledge_base

    kb = get_knowledge_base()
    print(f" {OK} Knowledge base: {len(kb.documents())} documents via {kb.backend}")

    print(
        f" {OK if s.api_key_set else WARN} API authentication {'enabled' if s.api_key_set else 'DISABLED (dev only)'}"
    )
    try:
        s.validate_production()
        print(
            f" {OK} Production guardrails satisfied" if s.app_env == "production" else f" {OK} Environment: {s.app_env}"
        )
    except RuntimeError as exc:
        print(f" {FAIL} {exc}")
        failures += 1

    print("\nAll checks passed." if not failures else f"\n{failures} check(s) failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
