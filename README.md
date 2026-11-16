<div align="center">

<img src="app/static/img/logo.svg" width="84" alt="SecureAIOps logo">

# SecureAIOps

**An agentic SOC copilot that triages security telemetry with a guarded multi-agent graph.**
It includes an AI firewall, MITRE ATT&CK mapping, explainable risk scoring, policy-grounded RAG and human approval gates.

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-multi--agent-1C3C3C)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-000000?logo=owasp)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C41230)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

<img src="docs/images/console-ransomware.png" alt="SecureAIOps investigation console triaging a ransomware precursor" width="100%">

</div>

---

## Why this exists

SOC teams are drowning in alerts, and "just ask an LLM" is not a safe answer.
A raw LLM can be prompt-injected, invent ATT&CK techniques, guess at severity and
leak secrets. Wired to tools, it can also act on production systems.

SecureAIOps applies one design principle throughout:

> **Deterministic enrichment, probabilistic reasoning.**
> Security-relevant facts (IOCs, ATT&CK mapping, risk score, approval gates) are computed by
> auditable code. The LLM classifies intent, routes requests and writes the narrative, and every LLM step has a
> deterministic fallback. The system degrades gracefully: it never fails open and never stops working.

## Features

| | |
|---|---|
| 🛡️ **Layered AI firewall** | Rule engine with Unicode/leetspeak/zero-width normalisation and base64 decoding, an LLM intent adjudicator, and per-request random boundary tags ("spotlighting") so attackers can't break out of the data region. |
| 🧠 **Multi-agent LangGraph** | A triage supervisor routes to **SOC Analyst**, **Threat Intel** or **Compliance Auditor** specialists. IOC extraction, ATT&CK mapping and retrieval run as a **parallel fan-out**. |
| 🎯 **MITRE ATT&CK mapping** | 44 curated techniques with evidence snippets and confidence. Kill-chain progression feeds the risk engine. |
| 📊 **Explainable risk engine** | An additive 0–100 score where every point is attributed to a factor (tactic severity, kill-chain length, technique combos such as *brute force → success* or *encryption + shadow-copy deletion*, privileged identities, external IPs). |
| 📚 **Policy-grounded RAG** | BM25 (offline) or Gemini embeddings on **pgvector**, with *concept-fusion retrieval* that rewrites raw telemetry into policy vocabulary. Answers cite the exact policy clauses they use. |
| 🔒 **Output guard** | DLP redaction (cloud keys, tokens, private keys, cards, credentials) plus a **system-prompt canary** that withholds any response that leaks instructions. |
| 🙋 **Human-on-the-loop** | Every containment action is marked `requires_approval`. Analysts approve or reject in the UI and the decision is written to the audit trail. |
| 🧾 **Audit trail** | Every analysis is persisted with a payload SHA-256, the full agent trace, guardrail verdicts and analyst decisions. |
| ⚡ **Live streaming UI** | A dependency-free SOC console under a strict CSP. Agent steps stream over SSE so you can watch the graph execute. |
| ✈️ **Air-gap friendly** | `LLM_PROVIDER=offline` runs the whole pipeline deterministically, so no data leaves the host. |

## Architecture

```mermaid
flowchart TD
    U[Analyst / SOAR] -->|POST /api/v1/analyze/stream| API[FastAPI<br/>auth · rate limit · CSP]
    API --> G{AI Firewall<br/>heuristics + LLM}
    G -- blocked --> B[Terminate + audit]
    G -- allowed --> S[Triage Supervisor]
    S --> I[IOC Extractor]
    S --> M[ATT&CK Mapper]
    S --> R[Knowledge Retriever<br/>BM25 / pgvector]
    I & M & R --> K[Risk Engine<br/>explainable score]
    K -->|route| A1[SOC Analyst]
    K -->|route| A2[Threat Intel]
    K -->|route| A3[Compliance Auditor]
    A1 & A2 & A3 --> O[Output Guard<br/>DLP + canary]
    O --> H[Analyst approval gates]
    O --> DB[(Audit trail<br/>PostgreSQL)]
```

<details>
<summary><b>More screenshots</b></summary>

| Prompt injection blocked | Architecture & controls |
|---|---|
| <img src="docs/images/blocked-injection.png" alt="Blocked prompt injection"> | <img src="docs/images/architecture.png" alt="Architecture view"> |

<img src="docs/images/incidents.png" alt="Incident audit trail">

</details>

## Security controls: OWASP Top 10 for LLM Applications

| Risk | Control in SecureAIOps |
|---|---|
| **LLM01** Prompt injection | Normalising rule firewall → LLM adjudicator → spotlighted inputs with random nonces |
| **LLM02** Sensitive information disclosure | Output DLP redaction before anything reaches the analyst |
| **LLM05** Improper output handling | Model output HTML-escaped before rendering; strict CSP blocks script injection |
| **LLM06** Excessive agency | Agents are read-only; state-changing actions are approval-gated and audited |
| **LLM07** System prompt leakage | Canary token in system prompts; leaking responses are withheld |
| **LLM08** Vector / embedding weaknesses | Retrieved passages are spotlighted as untrusted data |
| **LLM09** Misinformation | Severity and ATT&CK facts come from deterministic engines, never free-form model output |
| **LLM10** Unbounded consumption | Rate limiting, input size bounds, graph recursion limit, LLM timeouts |

See [SECURITY.md](SECURITY.md) for the full threat model and deployment hardening checklist.

## Quick start

### 1. Demo mode (no API key, no database)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/demo.py
```

Open **http://127.0.0.1:8000** and pick a scenario chip, for example *Ransomware precursor*,
*SSH brute force → success* or *Prompt injection*.

### 2. Live mode (Gemini)

```bash
cp .env.example .env        # set GEMINI_API_KEY
python scripts/doctor.py    # verifies config, DB and model connectivity without printing secrets
python scripts/demo.py --live
```

### 3. Production-like stack (Docker + PostgreSQL/pgvector)

```bash
cp .env.example .env        # set POSTGRES_PASSWORD, API_KEYS, GEMINI_API_KEY
docker compose up -d --build
docker compose exec api python scripts/ingest_knowledge.py   # embed policies into pgvector
# then set KB_BACKEND=pgvector in .env and restart the api service
```

The container runs as a non-root user on a read-only filesystem with all Linux capabilities dropped.
With `APP_ENV=production` the API **refuses to start** without API keys, with wildcard CORS, or on SQLite.

## API

Interactive docs are at `/docs` (disabled in production).

```bash
curl -s http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"message": "sshd[2211]: Failed password for root from 185.220.101.4 port 52144 ssh2"}' | jq .report.severity
```

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/analyze` | Run the full pipeline and return the report |
| `POST` | `/api/v1/analyze/stream` | Same, streamed as Server-Sent Events (`step` … `result`) |
| `GET` | `/api/v1/incidents` · `/{id}` | Audit trail |
| `POST` | `/api/v1/incidents/{id}/decisions` | Approve or reject a gated response action |
| `GET` | `/api/v1/stats` | KPIs (volume, blocked attacks, severity mix, latency) |
| `GET` | `/api/v1/knowledge/search?q=` | Search the policy knowledge base |
| `GET` | `/health` · `/ready` | Liveness and readiness probes |

## Project layout

```
app/
├── agents/        # LangGraph state, nodes, graph wiring, prompts, LLM provider abstraction
├── guardrails/    # input firewall (rules, normalisation, spotlighting) + output DLP/canary
├── intel/         # IOC extraction, ATT&CK catalog & mapper, risk engine, NIST 800-61 playbooks
├── rag/           # BM25 + pgvector knowledge base with graceful fallback
├── api/v1/        # FastAPI routes & schemas
├── core/          # settings, structured logging, auth / rate limit / security headers
├── db/            # SQLAlchemy models + repository (audit trail)
└── static/        # SOC console (vanilla JS/CSS, CSP-strict)
knowledge_base/    # sample internal policies (fictional)
scripts/           # demo launcher, doctor, pgvector ingestion
tests/             # 46 tests: guardrails, intel engines, pipeline, API security
```

## Development

```bash
pip install -r requirements-dev.txt
pre-commit install          # ruff + gitleaks on every commit
pytest                      # hermetic: offline engine, temporary SQLite
ruff check . && ruff format --check .
```

CI runs lint, tests on Python 3.11 and 3.12, Bandit SAST, `pip-audit`, Gitleaks secret scanning and a container build.

## Roadmap

- [ ] Connectors: Microsoft Sentinel / Splunk / Elastic alert ingestion and SOAR webhooks
- [ ] Threat-intel enrichment (VirusTotal, MISP, OpenCTI) behind the same approval model
- [ ] Sigma rule generation from confirmed incidents
- [ ] Conversation memory per case using a LangGraph checkpointer
- [ ] Guardrail evaluation harness with a public prompt-injection benchmark and regression scores in CI

## Disclaimer

SecureAIOps is a research and portfolio project. Its recommendations are advisory and must be validated by a
qualified analyst before any action is taken. The bundled policies are fictional sample data.

## License

[MIT](LICENSE)
