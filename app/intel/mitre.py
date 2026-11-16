"""Deterministic MITRE ATT&CK technique mapping."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from functools import lru_cache

from app.intel.mitre_catalog import TECHNIQUES


@dataclass(frozen=True)
class TechniqueMatch:
    id: str
    name: str
    tactic: str
    confidence: float
    evidence: str
    url: str

    def to_dict(self) -> dict:
        return asdict(self)


_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


def lookup(technique_id: str) -> dict | None:
    return next((t for t in TECHNIQUES if t["id"] == technique_id.upper()), None)


@lru_cache
def _compiled() -> list[tuple[dict, list[re.Pattern]]]:
    return [(t, [re.compile(p, re.I) for p in t["patterns"]]) for t in TECHNIQUES]


def _url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def map_techniques(text: str, max_results: int = 8) -> list[TechniqueMatch]:
    """Map free-text telemetry to ATT&CK techniques with evidence snippets.

    Confidence grows with the number of distinct patterns that fire for a
    technique (diminishing returns), capped at 0.95: a deterministic mapper
    should never claim certainty.
    """
    results: list[TechniqueMatch] = []
    explicit = {m.group(0).upper() for m in _TECHNIQUE_ID.finditer(text)}
    for technique, patterns in _compiled():
        if technique["id"] in explicit:
            results.append(
                TechniqueMatch(
                    technique["id"],
                    technique["name"],
                    technique["tactic"],
                    0.9,
                    "Technique explicitly referenced",
                    _url(technique["id"]),
                )
            )
            continue
        hits = [m for p in patterns if (m := p.search(text))]
        if not hits:
            continue
        first = min(hits, key=lambda m: m.start())
        m_start = (
            first.start() if first.end() - first.start() <= 90 else first.end() - 60
        )  # anchor long spans on their decisive end
        start, end = max(0, m_start - 30), min(len(text), first.end() + 30)
        # Snap to whitespace so evidence never starts/ends mid-token.
        while start > 0 and not text[start - 1].isspace() and m_start - start < 50:
            start -= 1
        while end < len(text) and not text[end].isspace() and end - first.end() < 50:
            end += 1
        snippet = ("…" if start > 0 else "") + " ".join(text[start:end].split()) + ("…" if end < len(text) else "")
        confidence = min(0.95, 0.55 + 0.15 * (len(hits) - 1))
        results.append(
            TechniqueMatch(
                id=technique["id"],
                name=technique["name"],
                tactic=technique["tactic"],
                confidence=round(confidence, 2),
                evidence=snippet,
                url=_url(technique["id"]),
            )
        )
    results.sort(key=lambda r: r.confidence, reverse=True)
    return results[:max_results]
