# Security Policy

SecureAIOps is a security tool, so its own security posture matters. This
document describes the threat model, the controls in place, and how to report
a vulnerability.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. You can expect an acknowledgement within 72 hours.

## Threat model (summary)

| Asset | Threat | Control |
|---|---|---|
| LLM behaviour | Direct prompt injection / jailbreak (OWASP LLM01) | Normalising rule-based AI firewall → LLM intent adjudicator → per-request random boundary tags ("spotlighting") |
| LLM behaviour | Indirect injection via retrieved documents (LLM01/LLM08) | Retrieved passages are spotlighted as untrusted data; deterministic facts are computed outside the LLM |
| System prompt | Prompt leakage (LLM07) | Per-process canary token; any response containing it is withheld |
| Secrets / PII | Sensitive information disclosure (LLM02) | Output DLP redaction (cloud keys, tokens, private keys, card numbers, credentials) |
| Production systems | Excessive agency (LLM06) | Agents are read-only; state-changing actions are `requires_approval` and recorded with the approver |
| Risk decisions | Hallucinated severity (LLM09) | Severity comes from an explainable additive risk engine, never from free-form model output |
| API | Abuse / brute force / DoS (LLM10) | Constant-time API-key auth, sliding-window rate limiting, bounded input size, bounded graph recursion |
| Web UI | XSS / clickjacking | Strict CSP (`script-src 'self'`, no inline code), output escaping before Markdown rendering, `X-Frame-Options: DENY` |
| Operations | Information leakage via errors | Generic error responses; details only in server logs with request correlation IDs |
| Supply chain | Vulnerable dependencies / leaked secrets | Dependabot, `pip-audit`, Bandit SAST and Gitleaks in CI; pre-commit secret scanning |

## Hardening checklist for deployment

- Set `APP_ENV=production`. The app **refuses to start** without `API_KEYS`,
  with a wildcard CORS origin, or with SQLite.
- Generate API keys with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
- Terminate TLS at a reverse proxy; HSTS is emitted automatically over HTTPS.
- Run the provided container (non-root, read-only filesystem, all capabilities dropped).
- Keep PostgreSQL on a private network (the compose file binds it to loopback).
- Ship JSON logs (`LOG_JSON=true`) to your SIEM; every analysis is persisted with a payload SHA-256 for audit.
- Set `LLM_PROVIDER=offline` where data must not leave your environment.

## Known limitations

- The in-process rate limiter is per replica; use a shared store (e.g. Redis) when scaling horizontally.
- Heuristic guardrails reduce, but cannot eliminate, prompt-injection risk. Treat model output as advisory.
- The bundled knowledge base contains **fictional sample policies** for demonstration only.
