"""Typed state shared by every node of the agent graph."""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict


class AgentState(TypedDict, total=False):
    # Inputs
    input: str
    session_id: str
    # Layer 1 — AI firewall
    guard: dict
    blocked: bool
    # Triage
    route: str
    route_reason: str
    # Parallel enrichment
    iocs: list[dict]
    techniques: list[dict]
    knowledge: list[dict]
    risk: dict
    # Specialist output + output guard
    report: dict
    output_guard: dict
    # Observability: each node appends its own step (reducer = list concat)
    trace: Annotated[list[dict], operator.add]
    degraded: Annotated[list[str], operator.add]
