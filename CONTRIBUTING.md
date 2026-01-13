# Contributing to FaraCore

## Project Layout
- `src/faracore/` — app, server, CLI, SDKs, UI assets
- `policies/` — default + examples
- `tests/` — integration + CLI + SDK tests
- `alembic/` — migrations (SQLite handled inline via `faracore migrate`)

## Setup
```bash
python3 -m pip install -e .[test]
PYTHONPATH=src python3 -m pytest
```

## Coding Standards
- Python: keep imports as `faracore.*`, add type hints and docstrings where non-obvious.
- Linting: `ruff` (config in `ruff.toml`); `flake8` optional.
- Tests: prefer pytest + httpx; use fixtures in `tests/conftest.py`.
- CLI: command name `faracore`, support `list|get|allow|deny|serve|migrate|policy-*`.

## Running
- Dev server: `faracore serve`
- DB init (SQLite): `faracore migrate`
- Policy check: `faracore policy-validate policies/default.yaml`

## Pull Request Checklist
- [ ] Tests pass (`python3 -m pytest`)
- [ ] Docs updated (README/CONTRIBUTING/examples)
- [ ] No new unused deps; imports use `faracore.*`
- [ ] Error messages consistent (HTTP status, JSON detail)
