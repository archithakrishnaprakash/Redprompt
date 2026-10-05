# RedPrompt development roadmap

Built phase-by-phase; each phase ships code **plus tests** and must not regress
earlier phases. "Verified" means tests were executed and passed in the build
environment; where PyPI is unreachable, the pure domain-core parts are verified
via the `tests_offline/` stdlib harness and the adapter layers are verified in CI.

| Phase | Deliverables | Verification |
|------:|--------------|--------------|
| 1 | Repo scaffold, Pydantic config (+YAML/env precedence), structured logging, redaction core, SQLAlchemy schema (11 tables), Alembic scaffold, Typer CLI (`version`, `doctor`, `config`) | `tests_offline` (config, redaction, enums) run live; DB/CLI covered by `tests/` pytest suite |
| 2 | Target manager (add/list/show/remove), provider adapters (OpenAI-compatible, Anthropic-compatible, Ollama, generic REST), async httpx client with timeout/retry/backoff/rate-limit, safety host-authorization checks | provider + safety unit tests (httpx MockTransport) |
| 3 | `SecurityTest` base interface, plugin discovery/registry, orchestrator (plan→execute→analyze→evidence→finding→risk→persist), workers, dry-run/safe-mode/scope guards | orchestrator + registry tests |
| 4 | Security-test plugins across prompt/data/rag/agent/api using publicly-documented, illustrative techniques against the lab; layered response analyzer | detection tests incl. false-positive/false-negative cases |
| 5 | Evidence repository (redaction + content hashing), finding model, transparent explainable risk engine, remediation mapping | risk determinism + evidence integrity tests |
| 6 | Retest engine, finding status lifecycle, scan-to-scan regression comparison | retest + regression tests |
| 7 | Inspection proxy (request/response capture, redaction, retention, logging) | proxy capture/redaction tests |
| 8 | FastAPI REST API + OpenAPI, dashboard pages, attack-surface graph, dashboard auth | API contract tests |
| 9 | Reporting: HTML (Jinja2), JSON, PDF, SARIF; `gate` command | report + SARIF schema tests |
| 10 | Local vulnerable lab (chatbot, RAG, agent, doc agent, REST API) + docker-compose | end-to-end scan-against-lab tests |
| 11 | Dockerfile, docker-compose, GitHub Actions (lint→type→test→security→build), gate + regression pipelines | CI green |
| 12 | Security review, dependency audit, STRIDE threat model, docs set, README, OWASP mapping, resume material, demo workflow | full suite + review checklist |

## Design decisions

- **Ports & adapters**: security-critical domain logic (redaction, analysis, risk,
  evidence, SARIF) is pure Python; SQLAlchemy/Typer/FastAPI are edge adapters. Keeps the
  trusted core small and portable, and independently testable.
- **Enums stored as VARCHAR + CHECK** (`native_enum=False`) so the schema is identical on
  SQLite and PostgreSQL and self-documenting.
- **Explicit config precedence** (`overrides > env > .redprompt.yml > defaults`) via a
  hand-written loader rather than implicit `BaseSettings` magic — auditable for a security tool.
- **Safety by default**: `require_authorization` + `block_public_targets` + loopback
  allow-list; dry-run and scope controls at scan time.
- **Honest detection**: statuses are `pass|fail|inconclusive|error|skipped`; heuristic
  checks are labeled; no fabricated findings; every finding traces to hashed evidence.
