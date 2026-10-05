<h1 align="center">RedPrompt</h1>
<p align="center"><b>AI Application Security Testing &amp; Red Teaming Platform</b></p>
<p align="center">
An extensible framework for the <b>authorized, controlled</b> security assessment of
LLM, RAG, and agentic applications — automated security tests, evidence collection,
explainable risk analysis, remediation tracking, regression testing, and professional reporting.
</p>
<p align="center">
Python 3.11+ · SQLAlchemy · FastAPI · Typer · httpx · Jinja2 · Docker · GitHub Actions · SARIF
</p>

---

> ### ⚠️ Authorized testing only
> RedPrompt tests AI systems you **own or are explicitly permitted to test**. By
> default it refuses non-authorized or non-loopback targets. It ships with a
> **local, intentionally vulnerable lab** so it can be demonstrated reproducibly
> without touching any third-party system. It generates **no** fabricated findings
> and contains **no** functionality for attacking arbitrary external systems.

## Why RedPrompt?

Traditional scanners (ZAP, Burp, nuclei) don't understand LLM-specific weaknesses —
prompt injection, insecure agent tool-use, RAG retrieval-authorization gaps, or
sensitive-context leakage. RedPrompt is a **security testing workbench for AI
applications** that maps to the OWASP Top 10 for LLMs, with the engineering rigor
of a real AppSec tool: a plugin test framework, an inspection proxy with redaction,
a transparent risk engine, tamper-evident evidence, retest/regression tracking, a
REST API + dashboard, and CI/CD gates (including SARIF for GitHub code scanning).

## Features

- **16+ security tests** across prompt / data / RAG / agent / API / file categories, OWASP-LLM-mapped.
- **Layered, honest detection** — refusals PASS, heuristics are labelled, statuses are `pass/fail/inconclusive/error/skipped`.
- **Extensible plugin architecture** with auto-discovery (`redprompt tests`).
- **Transparent risk engine** — explainable weighted score + confidence gate; no black box.
- **Tamper-evident evidence** — redacted before storage, SHA-256 verified.
- **Retest + regression** — finding lifecycle and scan-to-scan comparison with an explainable verdict.
- **Inspection proxy** — redacted, bounded request/response capture.
- **Reporting** — HTML, JSON, SARIF (+ optional PDF) and a CI `gate`.
- **REST API + dashboard** (FastAPI) with attack-surface visualization.
- **Vulnerable lab** — five insecure local apps + docker-compose.
- **DevSecOps** — Dockerfile, GitHub Actions (lint/type/test/SAST/build) and an AI-security gate workflow.
- **Safety by default** — authorization + loopback allow-list, rate limits, request budget, dry-run.

## Architecture

Ports & adapters: the security-critical domain core (safety, detection, risk,
evidence, SARIF) is pure Python; persistence (SQLAlchemy), CLI (Typer), and API
(FastAPI) are edge adapters. See [`docs/architecture.md`](docs/architecture.md).

```
Target AI app ─► HTTP client (+redacting inspector) ─► ScanEngine (pure, async)
   ─► layered detectors ─► Risk engine ─► Evidence(redacted+hashed)
   ─► Findings ─► Reporting (HTML/JSON/SARIF) ─► Gate / Retest / Regression
```

## Install

```bash
pip install -e ".[dev,api,lab]"
redprompt doctor          # checks env, DB, safety posture, deps, docker
```

> **Note:** the domain core is decoupled from the heavy libraries so it runs and
> is tested even where they can't be installed. `tests_offline/` (stdlib
> `unittest`) verifies the security logic — including full in-process scans of the
> lab; the `tests/` suite runs under `pytest` in CI.

## Quick start (against the vulnerable lab)

```bash
docker compose -f redprompt-lab/docker-compose.yml up --build     # start the lab
bash redprompt-lab/register-targets.sh                            # register 5 targets

redprompt scan lab-agent                                          # run an assessment
redprompt findings                                                # list findings
redprompt finding RP-AGENT-0001                                   # explainable risk + detail
redprompt evidence RP-AGENT-0001                                  # hash-verified evidence
redprompt report lab-agent --format html --format sarif           # reports
redprompt gate lab-agent --fail-on high                           # CI gate
redprompt serve --token "$TOKEN"                                  # dashboard + REST API
```

Example scan output:

```
RedPrompt Security Assessment
Target: lab-agent   Plan: 17 tests
Executed 17 · Passed 12 · Failed 3 · Inconclusive 1 · Skipped 1

Findings
RP-AGENT-0001  CRITICAL  94%  Unauthorized tool invocation
RP-AGENT-0002  HIGH      80%  Excessive agency
RP-AGENT-0003  MEDIUM    50%  Tool inventory disclosure
```

## CLI

`target` (add/list/show/remove/authorize) · `profile` · `scan` · `tests` ·
`findings` · `finding` · `evidence` · `retest` · `regression` · `report` ·
`gate` · `serve` · `config` · `doctor` · `version`.

## Documentation

[Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) ·
[Methodology](docs/methodology.md) · [Risk model](docs/risk-model.md) ·
[Evidence model](docs/evidence-model.md) · [Plugin development](docs/plugin-development.md) ·
[OWASP mapping](docs/owasp-mapping.md) · [API](docs/api.md) ·
[Deployment](docs/deployment.md) · [Roadmap](docs/roadmap.md)

## Testing

```bash
make test            # full pytest suite (68 tests, needs the full stack)
make test-offline    # 180 stdlib-unittest domain-core tests incl. lab E2E
```

## Security

RedPrompt follows secure-development practices itself: input validation, output
redaction, no `eval`/`exec`/shell, safe YAML, secrets never stored, non-root
images, dependency pinning, `bandit`/`pip-audit` in CI. See
[SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).

## Limitations

Detections are heuristic and evidence-based; absence of findings is not proof of
security. RedPrompt is not certified against any standard. The lab simulates
vulnerable behaviour deterministically (no real model).

## Roadmap

LLM10 (model theft) tests, model-assisted analysis (opt-in), richer agent
tool-graph analysis, PostgreSQL-first deployment guides. See [`docs/roadmap.md`](docs/roadmap.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
