"""Indicator-of-Compromise (IOC) extraction.

Deterministic, regex-based extraction that tolerates common *defanging*
conventions (``hxxp``, ``[.]``, ``(dot)``) and classifies network indicators
(private vs. public address space) so downstream scoring can reason about them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass

_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\(dot\)|\[dot\]", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
]

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_URL = re.compile(r"\bhttps?://[^\s\"'<>()\[\]]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# A pragmatic TLD allow-list keeps file names (``lsass.exe``, ``report.pdf``)
# from being reported as domains.
_TLDS = {
    "com",
    "net",
    "org",
    "io",
    "co",
    "info",
    "biz",
    "ru",
    "cn",
    "xyz",
    "top",
    "site",
    "online",
    "club",
    "app",
    "dev",
    "cloud",
    "tech",
    "me",
    "us",
    "uk",
    "de",
    "fr",
    "nl",
    "eu",
    "in",
    "br",
    "ir",
    "kp",
    "su",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "pw",
    "cc",
    "ws",
    "live",
    "shop",
    "store",
    "link",
    "click",
    "gov",
    "edu",
    "mil",
    "int",
    "ai",
    "sh",
    "to",
    "onion",
    "lol",
    "zip",
    "mov",
    "local",
    "corp",
    "lan",
    "internal",
    "nz",
    "au",
    "ca",
    "jp",
    "kr",
    "tw",
    "hk",
    "sg",
    "za",
    "mx",
    "ar",
    "es",
    "it",
    "pl",
    "ua",
    "by",
    "kz",
    "vn",
    "th",
    "id",
    "my",
    "ph",
    "pk",
    "ng",
    "ch",
    "se",
    "no",
    "fi",
    "dk",
    "be",
    "at",
    "cz",
    "ro",
    "gr",
    "pt",
    "tr",
    "il",
    "sa",
    "ae",
    "icu",
    "buzz",
    "monster",
    "rest",
}
_FILE_EXT_FALSE_POSITIVES = {"exe", "dll", "ps1", "bat", "sh", "py", "js", "zip", "log", "txt"}


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    context: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Return a non-clickable representation safe to display in reports."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def _classify_ip(raw: str) -> str:
    ip = ipaddress.ip_address(raw)
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "internal (RFC1918)"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved"
    return "external / public"


def extract_iocs(text: str, limit: int = 50) -> list[IOC]:
    """Extract de-duplicated IOCs, ordered by first appearance."""
    clean = refang(text)
    found: dict[tuple[str, str], IOC] = {}

    def add(ioc_type: str, value: str, context: str = "") -> None:
        key = (ioc_type, value.lower())
        if key not in found and len(found) < limit:
            found[key] = IOC(ioc_type, value, context)

    for m in _CVE.finditer(clean):
        add("cve", m.group(0).upper(), "vulnerability")
    for m in _URL.finditer(clean):
        add("url", m.group(0).rstrip(".,;"), "")
    for m in _EMAIL.finditer(clean):
        add("email", m.group(0).lower(), "")
    for m in _IPV4.finditer(clean):
        add("ipv4", m.group(0), _classify_ip(m.group(0)))
    for m in _SHA256.finditer(clean):
        add("sha256", m.group(0).lower(), "file hash")
    # Avoid double-reporting substrings of longer hashes.
    sha256_spans = [m.span() for m in _SHA256.finditer(clean)]
    for m in _SHA1.finditer(clean):
        if not any(s <= m.start() < e for s, e in sha256_spans):
            add("sha1", m.group(0).lower(), "file hash")
    long_spans = sha256_spans + [m.span() for m in _SHA1.finditer(clean)]
    for m in _MD5.finditer(clean):
        if not any(s <= m.start() < e for s, e in long_spans):
            add("md5", m.group(0).lower(), "file hash")

    email_domains = {i.value.split("@", 1)[1] for i in found.values() if i.type == "email"}
    url_text = " ".join(i.value for i in found.values() if i.type == "url")
    for m in _DOMAIN.finditer(clean):
        domain = m.group(0).lower().rstrip(".")
        tld = m.group(1).lower()
        if tld in _FILE_EXT_FALSE_POSITIVES or tld not in _TLDS:
            continue
        if domain in email_domains or _IPV4.fullmatch(domain):
            continue
        add("domain", domain, "seen in URL" if domain in url_text else "")

    return list(found.values())
