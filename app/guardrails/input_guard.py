"""Layer-1 AI firewall: deterministic prompt-injection & abuse detection.

Design principles
-----------------
* **Intent over artefacts.** SOC analysts legitimately paste malicious
  content (encoded PowerShell, exploit strings, phishing mails). We therefore
  score *instructions aimed at the assistant* and *requests to build
  offensive capability*, not the mere presence of attack artefacts.
* **Normalise before matching.** Unicode confusables, zero-width characters
  and leetspeak are folded so trivial obfuscation does not bypass rules.
* **Explainable.** Every verdict carries the rule ids that fired — auditable
  and tunable, unlike an opaque classifier.
* **Defence in depth.** This layer runs first (fast, free, deterministic);
  an LLM adjudicator (layer 2) reviews borderline payloads when configured.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
import unicodedata
from dataclasses import asdict, dataclass, field

_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    pattern: re.Pattern
    description: str


def _r(rule_id: str, category: str, weight: float, pattern: str, description: str) -> Rule:
    return Rule(rule_id, category, weight, re.compile(pattern, re.I | re.S), description)


RULES: list[Rule] = [
    # --- Instruction override (OWASP LLM01: Prompt Injection)
    _r(
        "PI-001",
        "instruction_override",
        0.75,
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|your|system)\b.{0,30}"
        r"\b(instructions?|prompts?|rules?|guidelines?|directives?|context)\b",
        "Attempts to override prior/system instructions",
    ),
    _r(
        "PI-002",
        "instruction_override",
        0.5,
        r"\b(new|updated|real|actual)\s+(instructions?|rules?|system prompt)\b\s*[:\-]",
        "Injects replacement instructions",
    ),
    _r(
        "PI-003",
        "instruction_override",
        0.45,
        r"\bfrom now on\b.{0,60}\b(you (will|must|are)|respond|answer|act)\b",
        "Persistent behaviour modification",
    ),
    # --- Role hijack / jailbreak personas
    _r(
        "JB-001",
        "jailbreak",
        0.7,
        r"\b(DAN|do anything now|developer mode|jailbr[eo]ak|god ?mode|unfiltered mode|no restrictions)\b",
        "Known jailbreak persona / mode",
    ),
    _r(
        "JB-002",
        "jailbreak",
        0.5,
        r"\b(you are|act as|pretend (to be|you are)|roleplay as|simulate)\b.{0,40}"
        r"\b(hacker|malicious|evil|unrestricted|uncensored|black ?hat|attacker)\b",
        "Role hijack towards an unrestricted/malicious persona",
    ),
    _r(
        "JB-003",
        "jailbreak",
        0.35,
        r"\b(hypothetically|for a (novel|story|movie)|in a fictional world)\b.{0,80}"
        r"\b(malware|exploit|ransomware|bypass|steal)\b",
        "Fictional framing used to extract harmful content",
    ),
    # --- System prompt / secret exfiltration (OWASP LLM07)
    _r(
        "EX-001",
        "prompt_exfiltration",
        0.7,
        r"\b(reveal|print|show|repeat|output|leak|dump|display)\b.{0,40}"
        r"\b(system prompt|initial prompt|hidden (prompt|instructions)|your instructions|developer message)\b",
        "Attempts to extract the system prompt",
    ),
    _r(
        "EX-002",
        "secret_exfiltration",
        0.65,
        r"\b(reveal|print|show|give|list|dump|leak|send)\b.{0,40}"
        r"\b(api[_ ]?keys?|secrets?|credentials?|passwords?|tokens?|env(ironment)? variables|\.env)\b"
        r"(?!.{0,40}\b(policy|requirements?|rotation|complexity)\b)",
        "Attempts to exfiltrate secrets/credentials",
    ),
    # --- Delimiter / context smuggling
    _r(
        "DL-001",
        "delimiter_injection",
        0.6,
        r"</?\s*(system|assistant|untrusted_input[\w-]*|payload|instructions?)\s*>|\[/?(INST|SYS)\]|<\|im_(start|end)\|>",
        "Chat-template or boundary tag smuggling",
    ),
    _r("DL-002", "delimiter_injection", 0.4, r"^\s*(system|assistant)\s*:\s", "Forged conversation role prefix"),
    # --- Tool / agent abuse (OWASP LLM06: Excessive Agency)
    _r(
        "AG-001",
        "tool_abuse",
        0.6,
        r"\b(execute|run|call|invoke)\b.{0,30}\b(shell|os\.system|subprocess|rm -rf|tool with|function)\b"
        r".{0,40}\b(on (the )?server|as root|without (approval|confirmation))\b",
        "Coerces the agent into unapproved actions",
    ),
    _r(
        "AG-002",
        "tool_abuse",
        0.55,
        r"\b(disable|turn off|remove|skip)\b.{0,30}\b(guardrails?|safety|filters?|content policy|firewall rules?|logging)\b"
        r".{0,40}\b(for (me|this)|now|immediately)\b",
        "Requests that the assistant disable controls",
    ),
    # --- Offensive capability development
    _r(
        "MAL-001",
        "malicious_request",
        0.7,
        r"\b(write|create|build|generate|develop|code|give me)\b.{0,40}"
        r"\b(ransomware|keylogger|rootkit|botnet|info-?stealer|credential stealer|polymorphic malware|"
        r"reverse shell payload|undetectable (malware|payload)|crypter)\b",
        "Requests creation of malware",
    ),
    _r(
        "MAL-002",
        "malicious_request",
        0.6,
        r"\b(how (do|can) i|help me|steps to)\b.{0,40}"
        r"\b(hack into|break into|exfiltrate data from|evade (edr|antivirus|detection)|deploy ransomware|"
        r"steal (passwords|credentials|cookies))\b",
        "Requests operational attack guidance",
    ),
]


@dataclass
class GuardVerdict:
    allowed: bool
    risk_score: float
    categories: list[str] = field(default_factory=list)
    matched_rules: list[dict] = field(default_factory=list)
    reason: str = ""
    layer: str = "heuristic"

    def to_dict(self) -> dict:
        return asdict(self)


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return text


def _decoded_views(text: str) -> list[str]:
    """Return extra views of the text: leetspeak-folded and base64-decoded."""
    views = [text.lower().translate(_LEET)]
    for blob in _B64_BLOB.findall(text)[:5]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            # PowerShell -enc payloads are UTF-16LE; try both encodings.
            for enc in ("utf-8", "utf-16-le"):
                try:
                    candidate = decoded.decode(enc)
                except UnicodeDecodeError:
                    continue
                if sum(c.isprintable() for c in candidate) / max(1, len(candidate)) > 0.9:
                    views.append(candidate)
                    break
        except (binascii.Error, ValueError):
            continue
    return views


def inspect(text: str, block_threshold: float = 0.65) -> GuardVerdict:
    """Score untrusted input. Combines rule weights with noisy-OR."""
    clean = normalise(text)
    views = [clean, *_decoded_views(clean)]
    hits: dict[str, Rule] = {}
    for rule in RULES:
        if any(rule.pattern.search(v) for v in views):
            hits[rule.id] = rule

    # Hidden-character smuggling is itself a strong signal.
    if _ZERO_WIDTH.search(text):
        hits["OB-001"] = Rule("OB-001", "obfuscation", 0.25, re.compile(""), "Zero-width / bidi control characters")

    # Noisy-OR: P(malicious) = 1 - Π(1 - w_i)
    p_clean = 1.0
    for rule in hits.values():
        p_clean *= 1.0 - rule.weight
    score = round(1.0 - p_clean, 3)

    categories = sorted({r.category for r in hits.values()})
    allowed = score < block_threshold
    reason = "No manipulation patterns detected" if not hits else ("; ".join(r.description for r in hits.values()))
    return GuardVerdict(
        allowed=allowed,
        risk_score=score,
        categories=categories,
        matched_rules=[
            {"id": r.id, "category": r.category, "weight": r.weight, "description": r.description}
            for r in hits.values()
        ],
        reason=reason,
    )


def spotlight(text: str) -> tuple[str, str]:
    """Wrap untrusted text in a per-request random boundary ("spotlighting").

    An attacker cannot pre-compute the closing tag, so they cannot break out
    of the data region. Any attempt to forge boundary-like tags is neutralised.
    """
    nonce = secrets.token_hex(6)
    tag = f"untrusted_input_{nonce}"
    safe = re.sub(r"</?\s*untrusted_input[\w-]*\s*>", "[removed-tag]", text, flags=re.I)
    return f"<{tag}>\n{safe}\n</{tag}>", tag
