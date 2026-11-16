"""Explainable risk scoring.

The score is a transparent, additive model rather than an LLM opinion: every
point is attributable to a factor an analyst can audit. LLMs may *explain*
the risk, but they never *decide* it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from app.intel.ioc import IOC
from app.intel.mitre import TechniqueMatch
from app.intel.mitre_catalog import TACTIC_WEIGHTS

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_AMPLIFIERS: list[tuple[re.Pattern, int, str]] = [
    (
        re.compile(r"\b(domain ?admin|enterprise admin|administrator|root|nt authority\\system)\b", re.I),
        10,
        "Privileged identity involved",
    ),
    (re.compile(r"\b(domain controller|\bdc\d*\b|ad server|krbtgt)\b", re.I), 10, "Tier-0 asset involved"),
    (
        re.compile(r"\b(production|prod-|payment|pci|customer data|pii|database server)\b", re.I),
        8,
        "Business-critical asset or regulated data",
    ),
    (
        re.compile(r"\b(succe(ss|eded)|accepted|logged in|authenticated)\b", re.I),
        6,
        "Evidence of successful action (not only attempts)",
    ),
    (re.compile(r"\b(multiple hosts|across \d+ (hosts|endpoints)|spread|worm)\b", re.I), 8, "Multi-host blast radius"),
    (
        re.compile(r"\b(clicked|opened the attachment|submitted (their )?credentials|enabled macros)\b", re.I),
        10,
        "Users interacted with the lure",
    ),
]


# Technique combinations that, together, indicate a materially worse situation.
_COMBOS: list[tuple[set[str], int, str]] = [
    ({"T1110", "T1078"}, 15, "Brute force followed by successful authentication (likely compromise)"),
    ({"T1486", "T1490"}, 15, "Encryption plus recovery inhibition (ransomware pattern)"),
    ({"T1003"}, 10, "Credential dumping enables domain-wide compromise"),
    ({"T1070"}, 8, "Anti-forensics: log clearing"),
    ({"T1041"}, 8, "Data leaving the environment"),
    ({"T1567"}, 8, "Data leaving the environment"),
]


@dataclass
class RiskAssessment:
    score: int
    severity: str
    factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def severity_for(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "INFO"


def assess_risk(text: str, techniques: list[TechniqueMatch], iocs: list[IOC]) -> RiskAssessment:
    factors: list[str] = []
    score = 0.0

    if techniques:
        tactics = {t.tactic for t in techniques}
        lead = max(techniques, key=lambda t: TACTIC_WEIGHTS.get(t.tactic, 0.4) * (0.7 + 0.3 * t.confidence))
        base = round(TACTIC_WEIGHTS.get(lead.tactic, 0.4) * (0.7 + 0.3 * lead.confidence) * 70)
        score += base
        factors.append(f"Most severe tactic: {lead.tactic} ({lead.id}) → +{base}")
        if len(tactics) >= 2:
            chain_bonus = min(24, (len(tactics) - 1) * 8)
            score += chain_bonus
            factors.append(f"Kill-chain progression across {len(tactics)} tactics → +{chain_bonus}")
        ids = {t.id.split(".")[0] for t in techniques}
        for combo, pts, label in _COMBOS:
            if combo <= ids:
                score += pts
                factors.append(f"{label} → +{pts}")

    external_ips = [i for i in iocs if i.type == "ipv4" and i.context.startswith("external")]
    if external_ips:
        bonus = min(10, 4 * len(external_ips))
        score += bonus
        factors.append(f"{len(external_ips)} external IP address(es) → +{bonus}")
    if any(i.type in {"sha256", "sha1", "md5"} for i in iocs):
        score += 5
        factors.append("File hash indicators present → +5")
    if any(i.type in {"url", "domain"} for i in iocs):
        score += 4
        factors.append("Network indicators (URL/domain) present → +4")

    if techniques:  # amplifiers only matter when malicious activity is observed
        for pattern, pts, label in _AMPLIFIERS:
            if pattern.search(text):
                score += pts
                factors.append(f"{label} → +{pts}")

    final = max(0, min(100, round(score)))
    if not factors:
        factors.append("No adversary behaviour or indicators detected")
    return RiskAssessment(score=final, severity=severity_for(final), factors=factors)
