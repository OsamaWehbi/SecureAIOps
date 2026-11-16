"""Application service that runs the agent graph and shapes its results."""

from __future__ import annotations

import time
from collections.abc import Iterator

from app.agents.graph import build_graph
from app.agents.llm import engine_label

RECURSION_LIMIT = 25


def _result(state: dict, started: float) -> dict:
    degraded = state.get("degraded", [])
    engine = engine_label() + (" (degraded: " + ", ".join(degraded) + ")" if degraded else "")
    return {
        "route": state.get("route", "blocked"),
        "blocked": bool(state.get("blocked")),
        "guard": state.get("guard", {}),
        "report": state.get("report", {}),
        "output_guard": state.get("output_guard", {}),
        "trace": state.get("trace", []),
        "engine": engine,
        "latency_ms": round((time.perf_counter() - started) * 1000),
    }


def analyze(text: str, session_id: str = "default") -> dict:
    started = time.perf_counter()
    state = build_graph().invoke(
        {"input": text, "session_id": session_id, "trace": [], "degraded": []},
        config={"recursion_limit": RECURSION_LIMIT},
    )
    return _result(state, started)


def analyze_stream(text: str, session_id: str = "default") -> Iterator[tuple[str, dict]]:
    """Yield ``("step", trace_entry)`` as nodes finish, then ``("result", result)``."""
    started = time.perf_counter()
    final: dict = {}
    for mode, chunk in build_graph().stream(
        {"input": text, "session_id": session_id, "trace": [], "degraded": []},
        config={"recursion_limit": RECURSION_LIMIT},
        stream_mode=["updates", "values"],
    ):
        if mode == "updates":
            for update in chunk.values():
                for step in (update or {}).get("trace", []):
                    yield "step", step
        elif mode == "values":
            final = chunk
    yield "result", _result(final, started)
