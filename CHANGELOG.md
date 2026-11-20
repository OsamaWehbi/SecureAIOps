# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Contributing guide, changelog, and issue and pull request templates.
- Live CI status badge in the README.

## [2.0.0]

### Added
- Multi-agent LangGraph pipeline with a triage supervisor and SOC Analyst, Threat Intel and Compliance Auditor specialists.
- Layered AI firewall with rule normalisation, an LLM intent adjudicator and spotlighted inputs.
- Output guard with DLP redaction and a system-prompt canary.
- MITRE ATT&CK mapping, explainable risk engine and NIST 800-61 playbooks.
- Policy-grounded RAG with BM25 and pgvector backends.
- FastAPI service with API-key auth, rate limiting, a strict CSP and an audit trail.
- SOC console with live streaming of agent steps.
- Docker and docker compose deployment, pre-commit hooks and a CI pipeline with lint, tests, Bandit, pip-audit and Gitleaks.
