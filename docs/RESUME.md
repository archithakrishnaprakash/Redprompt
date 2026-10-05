# RedPrompt — resume & interview material

## One-line description

**RedPrompt** — an extensible AI application security testing & red-teaming
platform for authorized assessment of LLM, RAG, and agentic apps, with automated
security tests, evidence collection, explainable risk scoring, regression
tracking, and SARIF/HTML reporting.

## Resume project description (short)

> Designed and built **RedPrompt**, a production-quality AI security testing
> framework (≈7k LOC, Python 3.11) for the *authorized* assessment of LLM/RAG/agent
> applications. Implemented a plugin architecture of 17 OWASP-LLM-mapped security
> tests (prompt injection, RAG retrieval-authorization, agent tool misuse, secret/PII
> leakage, API auth), a transparent risk engine, tamper-evident evidence, retest &
> regression tracking, a FastAPI dashboard, and CI/CD security gates with SARIF
> output. Ships a local vulnerable lab so scans are fully reproducible; verified by
> 248 tests including in-process end-to-end scans of the lab.

## Resume bullet points

- Built an **extensible security-test plugin framework** (auto-discovery, common
  interface) with **17 tests** across prompt/data/RAG/agent/API/file categories,
  mapped to the **OWASP Top 10 for LLMs**.
- Engineered a **ports-and-adapters** architecture: a pure, dependency-light
  domain core (detection, risk, evidence, SARIF) with SQLAlchemy/FastAPI/Typer as
  edge adapters — enabling **180 stdlib-only tests** to run anywhere, incl.
  in-process end-to-end scans via `httpx.ASGITransport`.
- Designed a **transparent, explainable risk engine** (weighted impact ×
  exploitability × exposure × confidence, with a confidence gate) — no black-box
  scores; every finding carries its full factor breakdown.
- Implemented **tamper-evident evidence**: secrets/PII redacted before storage,
  SHA-256 integrity hashing, and a verify step surfaced in the CLI/dashboard.
- Added an **inspection proxy** (redacted, bounded request/response capture),
  **retest** engine (finding lifecycle) and **security regression** comparison.
- Delivered a **FastAPI REST API + dashboard** with an attack-surface graph, and a
  **Typer + Rich CLI** (`scan`, `findings`, `report`, `gate`, `serve`, …).
- Built **DevSecOps**: Dockerfile, GitHub Actions (ruff/black/mypy/pytest/bandit/
  pip-audit/build) and an **AI-security gate** workflow that scans a vulnerable
  lab and uploads **SARIF** to GitHub code scanning.
- Applied **secure-development practices to the tool itself**: input validation,
  output redaction, no `eval`/`exec`/shell, safe YAML, secrets never persisted,
  non-root images, and a STRIDE threat model.
- Enforced **safety-by-default**: authorization required, loopback allow-list,
  rate limiting, per-target request budget, dry-run mode.

## Skills demonstrated

AI/LLM security · application security · secure SDLC · threat modeling · Python
(typed, async) · plugin architecture · SQLAlchemy + Alembic · FastAPI · Typer CLI
· httpx · automated testing (pytest + unittest) · CI/CD · Docker · SARIF / GitHub
code scanning · technical writing.

## Suggested interview demo (5 minutes)

1. **Frame it (30s).** "RedPrompt is a security workbench for AI apps — like
   ZAP/Burp but for LLM/RAG/agent weaknesses. Authorized testing only; it ships a
   local vulnerable lab so everything is reproducible."
2. **Show the lab + a scan (90s).**
   ```bash
   docker compose -f redprompt-lab/docker-compose.yml up -d --build
   bash redprompt-lab/register-targets.sh
   redprompt scan lab-agent
   ```
   Point out the honest counts (pass/fail/inconclusive) and the top finding.
3. **Explain a finding (60s).** `redprompt finding RP-AGENT-0001` — walk through
   the **explainable risk breakdown** and remediation. Then `redprompt evidence
   RP-AGENT-0001` — show **redacted, hash-verified** evidence.
4. **Retest + regression (45s).** Re-run after a "fix" → status flips to
   `remediated`; `redprompt regression lab-agent` shows the verdict.
5. **CI angle (45s).** Show `redprompt report … --format sarif` and the
   `redprompt-security.yml` workflow uploading SARIF to code scanning +
   `redprompt gate --fail-on high`.
6. **Design (30s).** "The security-critical core is pure Python and independently
   tested — 180 tests run without the DB/web stack, including in-process
   end-to-end scans of the lab."

### Likely questions & crisp answers

- *How do you avoid false positives?* Refusals count as PASS; detectors need a
  concrete indicator; low-confidence findings are gated to INFO; every finding has
  evidence for human triage.
- *Is this offensive tooling?* No — it's defensive/authorized-only: scope
  enforcement, loopback allow-list, a local lab, no capability to attack arbitrary
  systems, and no fabricated findings.
- *Why not just prompt an LLM to judge?* Model-assisted analysis is optional and
  labelled; core detection is deterministic and explainable so results are
  reproducible and auditable.
