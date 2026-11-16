"""LangGraph orchestration.

    input_guard ──blocked──▶ blocked_report ──▶ END
         │ allowed
         ▼
     supervisor ──┬──▶ ioc_extractor ───────┐
                  ├──▶ attack_mapper ───────┼──▶ risk_engine ──▶ {specialist} ──▶ output_guard ──▶ END
                  └──▶ knowledge_retriever ─┘

The enrichment fan-out runs in parallel (one LangGraph super-step); the join
waits for all three branches before scoring.
"""

from __future__ import annotations

from functools import lru_cache

from langgraph.graph import END, START, StateGraph

from app.agents import nodes
from app.agents.state import AgentState

SPECIALISTS = ("soc_analyst", "threat_intel", "compliance_auditor")


def _after_guard(state: AgentState) -> str:
    return "blocked_report" if state.get("blocked") else "supervisor"


def _to_specialist(state: AgentState) -> str:
    route = state.get("route", "threat_intel")
    return route if route in SPECIALISTS else "threat_intel"


@lru_cache
def build_graph():
    g = StateGraph(AgentState)
    g.add_node("input_guard", nodes.input_guard_node)
    g.add_node("blocked_report", nodes.blocked_report_node)
    g.add_node("supervisor", nodes.supervisor_node)
    g.add_node("ioc_extractor", nodes.ioc_node)
    g.add_node("attack_mapper", nodes.mitre_node)
    g.add_node("knowledge_retriever", nodes.rag_node)
    g.add_node("risk_engine", nodes.risk_node)
    g.add_node("soc_analyst", nodes.soc_analyst_node)
    g.add_node("threat_intel", nodes.threat_intel_node)
    g.add_node("compliance_auditor", nodes.compliance_auditor_node)
    g.add_node("output_guard", nodes.output_guard_node)

    g.add_edge(START, "input_guard")
    g.add_conditional_edges("input_guard", _after_guard, ["blocked_report", "supervisor"])
    g.add_edge("blocked_report", END)

    for branch in ("ioc_extractor", "attack_mapper", "knowledge_retriever"):
        g.add_edge("supervisor", branch)
    g.add_edge(["ioc_extractor", "attack_mapper", "knowledge_retriever"], "risk_engine")

    g.add_conditional_edges("risk_engine", _to_specialist, list(SPECIALISTS))
    for s in SPECIALISTS:
        g.add_edge(s, "output_guard")
    g.add_edge("output_guard", END)
    return g.compile()
