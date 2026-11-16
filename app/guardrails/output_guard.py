"""Layer-3 output guard: DLP redaction + system-prompt canary detection.

Addresses OWASP LLM02 (Sensitive Information Disclosure) and LLM07 (System
Prompt Leakage). Model output is treated as untrusted until it passes here.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass, field

# A per-process canary embedded in every system prompt. If it ever appears in
# model output, the model was manipulated into echoing its instructions.
CANARY = f"CANARY-{secrets.token_hex(8).upper()}"

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    (
        "password_assignment",
        re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*(?=[^\s,;]*[\d!@#$%^&*])[^\s,;]{6,}"),
    ),
    ("credit_card", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{3,4}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


@dataclass
class OutputVerdict:
    text: str
    redactions: list[dict] = field(default_factory=list)
    canary_leak: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("text")
        return d


def scrub(text: str) -> OutputVerdict:
    if CANARY in text:
        return OutputVerdict(
            text=(
                "The generated response was withheld: it contained protected system "
                "instructions (canary token detected). The event has been logged."
            ),
            canary_leak=True,
        )
    redactions: list[dict] = []
    for label, pattern in _SECRET_PATTERNS:
        count = 0

        def _sub(m: re.Match, _label: str = label) -> str:
            nonlocal count
            count += 1
            return f"[REDACTED:{_label}]"

        text = pattern.sub(_sub, text)
        if count:
            redactions.append({"type": label, "count": count})
    return OutputVerdict(text=text, redactions=redactions)
