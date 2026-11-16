"""Agent graph nodes.

Architecture: *deterministic enrichment, probabilistic reasoning*.
Security-relevant facts (IOCs, ATT&CK mapping, risk score, approval gates) are
computed by auditable code. The LLM — when available — classifies intent,
routes, and writes the narrative. Every LLM step has a deterministic fallback,
so the pipeline degrades gracefully instead of failing open or failing hard.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from functools import wraps
from itertools import zip_longest
from typing import Literal

from pydantic import BaseModel, Field

from app.agents import prompts
from app.agents.llm import LLMUnavailable, live, structured_call
from app.agents.state import AgentState
from app.core.config import get_settings
from app.guardrails import input_guard, output_guard
from app.intel.ioc import IOC, extract_iocs
from app.intel.mitre import TechniqueMatch, lookup, map_techniques
from app.intel.mitre_catalog import TACTIC_WEIGHTS
from app.intel.playbooks import detection_hints, recommend_actions
from app.intel.risk import RiskAssessment, assess_risk, severity_for
from app.rag.knowledge import get_knowledge_base

log = logging.getLogger(__name__)

Route = Literal["soc_analyst", "threat_intel", "compliance_auditor"]
ROUTE_LABELS = {
    "soc_analyst": "SOC Analyst",
    "threat_intel": "Threat Intel Analyst",
    "compliance_auditor": "Compliance Auditor",
}


def traced(node: str, label: str) -> Callable:
    """Decorator: time the node and append a structured trace step."""

    def deco(fn: Callable[[AgentState], dict]) -> Callable[[AgentState], dict]:
        @wraps(fn)
        def wrapper(state: AgentState) -> dict:
            t0 = time.perf_counter()
            try:
                update = fn(state)
            except Exception:
                log.exception("node %s failed", node)
                raise
            step = update.pop("_step", {})
            step = {
                "node": node,
                "label": label,
                "status": "ok",
                **step,
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
            update.setdefault("trace", []).append(step)
            return update

        return wrapper

    return deco


# =============================================================== 1. AI firewall
class GuardDecision(BaseModel):
    verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
    reason: str = Field(description="One sentence justification")


@traced("input_guard", "AI Firewall")
def input_guard_node(state: AgentState) -> dict:
    s = get_settings()
    verdict = input_guard.inspect(state["input"], s.guard_block_threshold)
    degraded: list[str] = []

    if verdict.allowed and live() and s.guard_use_llm:
        wrapped, _ = input_guard.spotlight(state["input"])
        try:
            decision = structured_call(GuardDecision, prompts.GUARD, wrapped)
            verdict.layer = "heuristic+llm"
            if decision.verdict == "MALICIOUS":
                verdict.allowed = False
                verdict.risk_score = max(verdict.risk_score, 0.9)
                verdict.categories = sorted({*verdict.categories, "llm_semantic"})
                verdict.reason = f"LLM adjudicator: {decision.reason}"
            elif decision.verdict == "SUSPICIOUS":
                verdict.risk_score = max(verdict.risk_score, 0.45)
                verdict.reason = f"{verdict.reason} | LLM: {decision.reason}"
        except LLMUnavailable:
            degraded.append("input_guard")

    status = "ok" if verdict.allowed else "blocked"
    detail = f"Risk {verdict.risk_score:.2f} · {verdict.layer}" + (
        f" · {', '.join(r['id'] for r in verdict.matched_rules)}" if verdict.matched_rules else ""
    )
    return {
        "guard": verdict.to_dict(),
        "blocked": not verdict.allowed,
        "degraded": degraded,
        "_step": {"status": status, "detail": detail},
    }


def blocked_report_node(state: AgentState) -> dict:
    g = state["guard"]
    rules = ", ".join(r["id"] for r in g.get("matched_rules", [])) or "semantic classifier"
    summary = (
        "### Request blocked by the AI firewall\n"
        "The input was classified as an attempt to **manipulate the assistant** rather than a "
        "security analysis request, so no agent, tool or knowledge source was invoked.\n\n"
        f"- **Detection layer:** {g.get('layer')}\n"
        f"- **Firewall risk score:** {g.get('risk_score', 0):.2f}\n"
        f"- **Categories:** {', '.join(g.get('categories', [])) or 'n/a'}\n"
        f"- **Rules fired:** {rules}\n\n"
        "This event has been written to the audit log. If this is a false positive, rephrase the "
        "request as an analysis task (e.g. *“Analyse this prompt-injection sample: …”*)."
    )
    offensive = "malicious_request" in g.get("categories", [])
    report = {
        "title": "Offensive-capability request blocked" if offensive else "Prompt-injection attempt blocked",
        "verdict": "blocked",
        "severity": "HIGH",
        "confidence": round(min(0.99, g.get("risk_score", 0.9)), 2),
        "summary": summary,
        "key_findings": [r["description"] for r in g.get("matched_rules", [])] or [g.get("reason", "")],
        "risk": {
            "score": round(g.get("risk_score", 0) * 100),
            "severity": "HIGH",
            "factors": ["OWASP LLM01 — Prompt Injection"],
        },
        "techniques": [],
        "iocs": [],
        "references": [],
        "actions": [
            {
                "phase": "Analysis",
                "action": "Review the requesting identity's recent activity for abuse patterns",
                "priority": "P2",
                "requires_approval": False,
            },
            {
                "phase": "Containment",
                "action": "Revoke the API key if repeated injection attempts are observed",
                "priority": "P2",
                "requires_approval": True,
            },
        ],
        "specialist": "AI Firewall",
    }
    return {
        "report": report,
        "route": "blocked",
        "trace": [
            {
                "node": "blocked",
                "label": "Terminate",
                "status": "blocked",
                "detail": "Transaction terminated · audit logged",
                "ms": 0.0,
            }
        ],
    }


# ================================================================== 2. Triage
class RouteDecision(BaseModel):
    route: Route
    rationale: str = Field(description="One sentence")


_COMPLIANCE = re.compile(
    r"\b(polic(y|ies)|complian\w*|nist|iso ?27001|pci|gdpr|hipaa|soc ?2|cis control|allowed|permitted|"
    r"prohibited|required|requirement|regulat\w*|audit(or)?|govern\w*|change request|"
    r"(can|may|should|must) (we|i|users?|employees?|staff|admins?)|are we|do we need)\b",
    re.I,
)
_INTEL = re.compile(
    r"\b(cve-\d{4}-\d+|apt\s?\d+|threat actor|malware family|lazarus|fin\d+|what is t\d{4}|"
    r"explain|ttps?|campaign|ioc lookup|reputation)\b",
    re.I,
)
_TELEMETRY = re.compile(
    r"(\b(event ?id|sshd|failed|alert|log(s)?|detected|process|cmd\.exe|powershell|src[_ ]?ip|dst|"
    r"user(name)?=|host(name)?=|edr|siem|firewall deny|connection|login|logon)\b|\d{1,3}(\.\d{1,3}){3})",
    re.I,
)


_QUESTION = re.compile(r"^\s*(what|how|why|which|when|who|is|are|can|does|do|should|explain|describe)\b|\?\s*$", re.I)


def is_informational(text: str, iocs: list[IOC]) -> bool:
    """A question with no telemetry or indicators describes no observed activity to score."""
    return not iocs and not _TELEMETRY.search(text) and bool(_QUESTION.search(text))


def offline_route(text: str) -> tuple[str, str]:
    scores = {
        "compliance_auditor": len(_COMPLIANCE.findall(text)) * 1.4,
        "threat_intel": len(_INTEL.findall(text)) * 1.2,
        "soc_analyst": len(_TELEMETRY.findall(text)) * 1.0,
    }
    route = max(scores, key=scores.get)
    if scores[route] == 0:
        return "threat_intel", "No telemetry or policy signals; handled as a general security question"
    signals = {
        "compliance_auditor": "policy/compliance",
        "threat_intel": "threat-intel",
        "soc_analyst": "telemetry/log",
    }
    return route, f"Strongest signal: {signals[route]} keywords (score {scores[route]:.1f})"


@traced("supervisor", "Triage Supervisor")
def supervisor_node(state: AgentState) -> dict:
    degraded: list[str] = []
    route, reason = offline_route(state["input"])
    method = "keyword classifier"
    if live():
        wrapped, _ = input_guard.spotlight(state["input"])
        try:
            d = structured_call(RouteDecision, prompts.ROUTER, wrapped)
            route, reason, method = d.route, d.rationale, "LLM router"
        except LLMUnavailable:
            degraded.append("supervisor")
    return {
        "route": route,
        "route_reason": reason,
        "degraded": degraded,
        "_step": {"detail": f"→ {ROUTE_LABELS[route]} · {method}"},
    }


# ========================================================= 3. Parallel enrichment
@traced("ioc_extractor", "IOC Extractor")
def ioc_node(state: AgentState) -> dict:
    iocs = extract_iocs(state["input"])
    kinds = sorted({i.type for i in iocs})
    return {
        "iocs": [i.to_dict() for i in iocs],
        "_step": {"detail": f"{len(iocs)} indicator(s)" + (f" · {', '.join(kinds)}" if kinds else "")},
    }


@traced("attack_mapper", "ATT&CK Mapper")
def mitre_node(state: AgentState) -> dict:
    techniques = map_techniques(state["input"])
    return {
        "techniques": [t.to_dict() for t in techniques],
        "_step": {
            "detail": f"{len(techniques)} technique(s)"
            + (f" · {', '.join(t.id for t in techniques[:4])}" if techniques else "")
        },
    }


@traced("knowledge_retriever", "Knowledge Retriever")
def rag_node(state: AgentState) -> dict:
    kb = get_knowledge_base()
    k = get_settings().kb_top_k
    # Concept retrieval: raw telemetry rarely shares vocabulary with policy prose,
    # so issue a second query built from the ATT&CK concepts the text exhibits
    # (a lightweight form of HyDE / query rewriting) and fuse the result lists.
    concepts = sorted(
        map_techniques(state["input"]),
        key=lambda t: (t.id.split(".")[0] in _CONCEPT_HINTS, TACTIC_WEIGHTS.get(t.tactic, 0)),
        reverse=True,
    )[:2]
    concept_query = " ".join(_CONCEPT_HINTS.get(t.id.split(".")[0], t.name) for t in concepts)
    concept_hits = kb.search(concept_query, k) if concept_query else []
    raw_hits = kb.search(state["input"], k)
    # Round-robin fusion so both views contribute their best passage first.
    interleaved = [h for pair in zip_longest(concept_hits, raw_hits) for h in pair if h is not None]
    seen: set[tuple[str, str]] = set()
    hits = [h for h in interleaved if (h.source, h.section) not in seen and not seen.add((h.source, h.section))][:k]
    mode = "raw + concept fusion" if concept_query else "raw query"
    return {
        "knowledge": [h.to_dict() for h in hits],
        "_step": {"detail": f"{len(hits)} passage(s) · {kb.backend} · {mode}"},
    }


# Policy-vocabulary hints per technique family, used for concept retrieval.
_CONCEPT_HINTS = {
    "T1486": "ransomware response isolate backups",
    "T1490": "ransomware backups recovery",
    "T1110": "failed sign-in attempts lockout brute force",
    "T1078": "compromised privileged account escalation",
    "T1566": "phishing email reporting clicked link credentials",
    "T1567": "personal cloud storage upload exfiltration",
    "T1041": "outbound transfer data exfiltration",
    "T1021": "remote desktop lateral movement",
    "T1562": "firewall changes disabling security tools",
    "T1098": "privileged group membership PAM",
    "T1003": "credential dumping privileged accounts",
}


@traced("risk_engine", "Risk Engine")
def risk_node(state: AgentState) -> dict:
    iocs = [IOC(**i) for i in state.get("iocs", [])]
    techniques = [TechniqueMatch(**t) for t in state.get("techniques", [])]
    if is_informational(state["input"], iocs):
        reason = "Policy question" if state.get("route") == "compliance_auditor" else "Knowledge question"
        risk = RiskAssessment(0, "INFO", [f"{reason} — no observed activity to score"])
    else:
        risk = assess_risk(state["input"], techniques, iocs)
    return {"risk": risk.to_dict(), "_step": {"detail": f"{risk.score}/100 · {risk.severity}"}}


# ================================================================ 4. Specialists
class SpecialistOutput(BaseModel):
    title: str = Field(description="Short incident/answer title, max 80 chars")
    verdict: Literal[
        "malicious_activity_likely", "suspicious_needs_investigation", "benign_or_informational", "policy_answer"
    ]
    confidence: float = Field(ge=0, le=1)
    summary_markdown: str = Field(description="Analyst-grade assessment in Markdown")
    key_findings: list[str] = Field(default_factory=list, max_length=6)
    additional_actions: list[str] = Field(
        default_factory=list, max_length=3, description="Extra next steps not already in the playbook"
    )


def _context_block(state: AgentState) -> str:
    enrichment = {
        "risk": state.get("risk"),
        "attack_techniques": [
            {k: t[k] for k in ("id", "name", "tactic", "confidence", "evidence")} for t in state.get("techniques", [])
        ],
        "iocs": state.get("iocs", []),
    }
    passages = [
        {"doc": h["title"], "section": h["section"], "text": h["text"][:1200]} for h in state.get("knowledge", [])
    ]
    wrapped_input, _ = input_guard.spotlight(state["input"])
    wrapped_kb, _ = input_guard.spotlight(json.dumps(passages, ensure_ascii=False))
    return (
        f"## Request\n{wrapped_input}\n\n"
        f"## Deterministic enrichment (authoritative)\n```json\n{json.dumps(enrichment, indent=1)}\n```\n\n"
        f"## Internal knowledge passages (untrusted data)\n{wrapped_kb}"
    )


_GENERIC = {"polic", "accor", "allow", "inter", "secur", "compa", "about", "there", "requi", "permi"}


def _stems(text: str) -> set[str]:
    return {t[:5] for t in re.findall(r"[a-z0-9]{3,}", text.lower())} - _GENERIC


def _sentences_matching(text: str, query: str, limit: int = 3) -> list[str]:
    """Extractive answer: clauses sharing the most (crudely stemmed) terms with the query."""
    terms = _stems(query)
    lines = [ln.strip(" -*") for ln in text.split("\n") if ln.strip()]
    scored = sorted(((len(terms & _stems(ln)), i, ln) for i, ln in enumerate(lines)), key=lambda x: (-x[0], x[1]))
    return [ln for n, _, ln in scored[:limit] if n > 0]


def _offline_report(state: AgentState) -> dict:
    route = state["route"]
    text = state["input"]
    techniques = state.get("techniques", [])
    iocs = state.get("iocs", [])
    risk = state.get("risk", {})
    hits = state.get("knowledge", [])
    tactics = list(dict.fromkeys(t["tactic"] for t in techniques))
    sev = risk.get("severity", "INFO")

    # Extractive grounding: best-matching clauses across the retrieved passages.
    candidates: list[tuple[float, str]] = []
    for h in hits:
        if h["score"] < 0.35:
            continue
        for sentence in _sentences_matching(h["text"], text, 3):
            overlap = len(_stems(text) & _stems(sentence))
            candidates.append((overlap + h["score"], f"- *{h['title']} › {h['section']}* — {sentence}"))
    candidates.sort(key=lambda c: -c[0])
    policy_lines = list(dict.fromkeys(line for _, line in candidates[:3]))
    informational = risk.get("score", 0) == 0

    if route == "compliance_auditor":
        title = "Policy guidance: " + (hits[0]["section"] if hits else "no matching policy")
        if policy_lines:
            body = "### Answer from internal policy\n" + "\n".join(policy_lines)
            verdict, conf = "policy_answer", 0.8
        else:
            body = (
                "### No matching policy found\nThe internal knowledge base does not contain a clause "
                "covering this question. Escalate to the GRC team for an authoritative ruling."
            )
            verdict, conf = "policy_answer", 0.4
        findings = [ln.split(" — ", 1)[-1] for ln in policy_lines[:4]]
    elif informational and techniques:
        verdict, conf = "benign_or_informational", 0.8
        title = "Threat brief: " + ", ".join(t["id"] for t in techniques[:3])
        body = "### Technique brief\n"
        for t in techniques[:3]:
            body += f"- **{t['id']} — {t['name']}** · tactic *{t['tactic']}* · [ATT&CK reference]({t['url']})\n"
        body += "\n### Detection opportunities\n" + "\n".join(
            f"- **{tac}:** {hint}" for tac in tactics for hint in detection_hints(tac)
        )
        if policy_lines:
            body += "\n\n### Related internal policy\n" + "\n".join(policy_lines)
        findings = [f"{t['id']} {t['name']} ({t['tactic']})" for t in techniques[:4]]
    elif techniques:
        verdict = "malicious_activity_likely" if sev in {"HIGH", "CRITICAL"} else "suspicious_needs_investigation"
        conf = round(min(0.92, 0.5 + 0.08 * len(techniques) + 0.003 * risk.get("score", 0)), 2)
        lead = max(techniques, key=lambda t: TACTIC_WEIGHTS.get(t["tactic"], 0.4))
        title = lead["name"].split(": ")[-1] + (f" · {len(tactics)}-stage kill chain" if len(tactics) > 1 else "")
        stage = " → ".join(tactics)
        body = (
            f"### Assessment\nActivity is consistent with **{len(techniques)} ATT&CK technique(s)** spanning "
            f"**{stage}**. The explainable risk engine scored it **{risk.get('score')}/100 ({sev})**.\n\n"
            "### Observed behaviour\n"
            + "\n".join(
                f"- `{t['id']}` **{t['name']}** ({t['tactic']}) — evidence: “{t['evidence']}”" for t in techniques[:5]
            )
        )
        if iocs:
            ext = [i for i in iocs if i["type"] == "ipv4" and i["context"].startswith("external")]
            body += f"\n\n### Indicators\n{len(iocs)} IOC(s) extracted" + (
                f", including **{len(ext)} external IP(s)** that should be blocked and enriched." if ext else "."
            )
        if policy_lines:
            body += "\n\n### Policy context\n" + "\n".join(policy_lines)
        findings = [f"{t['id']} · {t['name']} ({t['tactic']})" for t in techniques[:6]]
    else:
        verdict, conf = "benign_or_informational", 0.55
        title = "No adversary behaviour detected"
        body = (
            "### Assessment\nNo ATT&CK technique patterns or high-risk indicators were identified in the supplied text."
        )
        if iocs:
            body += f"\n\n{len(iocs)} indicator(s) were extracted and are ready for reputation enrichment."
        for t_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, re.I):
            if t := lookup(t_id):
                body += f"\n\n**{t['id']} — {t['name']}** belongs to the *{t['tactic']}* tactic."
        if policy_lines:
            body += "\n\n### Related policy\n" + "\n".join(policy_lines)
        findings = risk.get("factors", [])[:3]

    body += (
        "\n\n> **Scope:** automated triage of the supplied text only — no live SIEM/EDR access. "
        "Validate findings before executing containment actions."
    )
    return {
        "title": title[:80],
        "verdict": verdict,
        "confidence": conf,
        "summary": body,
        "key_findings": findings[:6],
        "extra_actions": [],
    }


def _specialist(route: str) -> Callable[[AgentState], dict]:
    @traced(route, ROUTE_LABELS[route])
    def node(state: AgentState) -> dict:
        degraded: list[str] = []
        method = "deterministic analyst"
        draft = _offline_report(state)
        if live():
            try:
                out = structured_call(SpecialistOutput, prompts.SPECIALISTS[route], _context_block(state))
                draft = {
                    "title": out.title[:80],
                    "verdict": out.verdict,
                    "confidence": round(out.confidence, 2),
                    "summary": out.summary_markdown,
                    "key_findings": out.key_findings,
                    "extra_actions": out.additional_actions,
                }
                method = "LLM reasoning"
            except LLMUnavailable:
                degraded.append(route)

        risk = state.get("risk", {"score": 0, "severity": "INFO", "factors": []})
        techniques = [TechniqueMatch(**t) for t in state.get("techniques", [])]
        iocs = [IOC(**i) for i in state.get("iocs", [])]
        if risk.get("score", 0) == 0 and not iocs:
            actions: list[dict] = []  # nothing observed -> nothing to respond to
        else:
            actions = recommend_actions(techniques, iocs, risk.get("severity", "INFO"))
        for extra in draft.pop("extra_actions", []):
            actions.append(
                {"phase": "Analysis", "action": extra, "priority": "P2", "requires_approval": True, "source": "llm"}
            )

        report = {
            **draft,
            "severity": risk.get("severity", severity_for(risk.get("score", 0))),
            "risk": risk,
            "techniques": state.get("techniques", []),
            "iocs": state.get("iocs", []),
            "references": state.get("knowledge", []),
            "actions": actions,
            "specialist": ROUTE_LABELS[route],
        }
        return {
            "report": report,
            "degraded": degraded,
            "_step": {"detail": f"{method} · {len(actions)} action(s)", "status": "warn" if degraded else "ok"},
        }

    node.__name__ = f"{route}_node"
    return node


soc_analyst_node = _specialist("soc_analyst")
threat_intel_node = _specialist("threat_intel")
compliance_auditor_node = _specialist("compliance_auditor")


# ============================================================== 5. Output guard
@traced("output_guard", "Output Guard")
def output_guard_node(state: AgentState) -> dict:
    report = dict(state["report"])
    total: list[dict] = []
    leak = False
    for field_name in ("summary", "title"):
        v = output_guard.scrub(report.get(field_name, ""))
        report[field_name] = v.text
        total += v.redactions
        leak |= v.canary_leak
    findings = []
    for f in report.get("key_findings", []):
        v = output_guard.scrub(f)
        findings.append(v.text)
        total += v.redactions
        leak |= v.canary_leak
    report["key_findings"] = findings
    if leak:
        report["verdict"] = "blocked"
        report["key_findings"] = ["System-prompt canary detected in model output"]
    n = sum(r["count"] for r in total)
    detail = "canary leak — response withheld" if leak else (f"{n} redaction(s)" if n else "clean · no secrets/PII")
    return {
        "report": report,
        "output_guard": {"redactions": total, "canary_leak": leak},
        "_step": {"status": "blocked" if leak else ("warn" if n else "ok"), "detail": detail},
    }
