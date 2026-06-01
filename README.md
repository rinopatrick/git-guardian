# Git Guardian

AI-assisted supply chain security scanner for npm packages.

Git Guardian helps security-minded developers quickly triage dependency risk by combining:
- deterministic checks (patterns, typosquatting heuristics), and
- optional LLM-assisted analysis for deeper review.

## Why this project exists

Modern software depends on large third-party ecosystems. Dependency attacks (typosquatting, malicious post-install scripts, obfuscated payloads) can slip into normal workflows. This project provides a practical, developer-friendly scanner to catch risky signals early.

## Features

- Scan npm packages for suspicious patterns
- Detect typosquatting candidates
- Optional AI-assisted code risk analysis
- Export findings as reports
- CLI + API-oriented architecture for integration

## Quick start

### 1) Install

```bash
pip install -e .
```

### 2) Basic usage

```bash
# Scan one package
git-guardian scan lodash

# Deep analysis
git-guardian scan express --deep

# Scan lockfile dependencies
git-guardian scan-lockfile package-lock.json
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

## Architecture (high level)

- `src/git_guardian/` — core scanner + services
- `tests/` — unit/integration tests
- `scripts/` — utility scripts and helpers

## Production-readiness status

Current state: **engineering sample / pre-production**.

What is already in place:
- Structured Python package with test suite
- Clear dependency management via `pyproject.toml`
- Database-backed scanning state

What should be completed before production deployment:
1. CI gate (tests + lint + type checks) on every push/PR
2. Containerization + deployment manifests
3. Secrets management and runtime hardening
4. Signed release process and SBOM generation
5. Alerting/monitoring and documented SLA

## Relevance to AI safety/alignment work

This repo is directly relevant to safety engineering practice:
- adversarial mindset (searching for evasive/malicious behavior),
- systematic evaluation design,
- risk triage and reproducible reporting.

## License

MIT
