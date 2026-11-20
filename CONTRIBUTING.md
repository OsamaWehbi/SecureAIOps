# Contributing to SecureAIOps

Thanks for your interest in improving SecureAIOps. Contributions of all sizes are welcome, including bug reports, documentation fixes, new ATT&CK techniques, guardrail test cases and connectors.

## Getting set up

```bash
git clone https://github.com/OsamaWehbi/SecureAIOps.git
cd SecureAIOps
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pre-commit install
```

The default configuration runs fully offline (`LLM_PROVIDER=offline`), so you do not need an API key to develop or run the tests.

## Before you open a pull request

```bash
ruff check app tests scripts
ruff format --check app tests scripts
pytest
```

CI runs the same checks on Python 3.11 and 3.12, plus Bandit, pip-audit and Gitleaks.

## Guidelines

- Open an issue first for larger changes so we can agree on the approach.
- Keep pull requests focused. One topic per PR is easier to review.
- Use conventional commit messages such as `feat`, `fix`, `docs`, `test` and `chore`.
- Add or update tests for any behavior change, especially in `app/guardrails` and `app/intel`.
- Security-relevant facts (risk score, ATT&CK mapping, approval gates) must stay deterministic. The LLM may classify, route and narrate, but it must not decide them.
- Never commit secrets, real incident data or customer telemetry. Use the fictional sample data in `knowledge_base/` as a model.

## Reporting security issues

Please do not open a public issue for a vulnerability. Follow the process in [SECURITY.md](SECURITY.md).
