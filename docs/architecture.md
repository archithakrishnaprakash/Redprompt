# Architecture

RedPrompt is organised as **ports and adapters** (hexagonal). The security-critical
domain logic is pure Python with no heavy dependencies; infrastructure concerns
(database, CLI, HTTP, web API) are adapters at the edges. This keeps the trusted
core small, portable, and independently testable.

```
                         Target AI application
                     (LLM / RAG / Agent / API / docs)
                                   ▲
                                   │ HTTP (provider adapter)
                    ┌──────────────┴───────────────┐
                    │        AsyncHTTPClient        │  rate-limit · retry · budget
                    │        + TrafficInspector     │  redacted capture
                    └──────────────┬───────────────┘
                                   │
        ┌──────────────────────────────────────────────────────┐
        │                    Domain core (pure)                 │
        │  safety · providers · tests_plugins · analysis        │
        │  risk · evidence · regression · reporting(sarif/json) │
        └───────────┬───────────────────────────┬──────────────┘
     ScanEngine (pure, async)            Formatters (pure)
                    │                             │
        ┌───────────┴───────────┐     ┌───────────┴───────────┐
        │   Orchestrator (DB)   │     │  Report builder (DB)  │
        │   RetestEngine (DB)   │     └───────────────────────┘
        └───────────┬───────────┘
             SQLAlchemy models
                    │
     ┌──────────────┼──────────────┐
   Typer CLI    FastAPI API     Dashboard
```

## Layers

| Layer | Modules | Depends on | Pure? |
|-------|---------|-----------|-------|
| Domain core | `safety`, `redaction`, `enums`, `analysis`, `risk`, `evidence`, `regression`, `reporting/{data,sarif,json,gate}`, `tests_plugins` | stdlib, pydantic, httpx, jinja2 | ✅ |
| Execution | `core/engine` (ScanEngine) | domain core | ✅ (no DB) |
| Providers | `providers/*`, `http_client`, `proxy` | httpx | ✅ |
| Persistence | `db/*`, `core/orchestrator`, `retest`, `findings`, `reporting/builder` | SQLAlchemy | ✗ |
| Interfaces | `cli/*` (Typer), `api/*` (FastAPI) | persistence | ✗ |

## Key data flow (a scan)

```
Target ─► Safety check ─► Test plan ─► ScanEngine (async, bounded concurrency)
      ─► per test: provider.generate ─► layered detectors ─► DetectionResult
      ─► Orchestrator: TestExecution + redacted/hashed Evidence
      ─► FAIL ⇒ RiskEngine ⇒ Finding (explainable severity)
      ─► Scan counters ⇒ Report (HTML/JSON/SARIF) ⇒ Gate
```

## Why this shape

- **Testability without the full stack.** The core and `ScanEngine` run under a
  stdlib `unittest` harness (`tests_offline/`) with only pydantic/httpx/jinja2 —
  including full end-to-end scans of the lab via `httpx.ASGITransport`. The DB
  and web layers are covered by the `pytest` suite in CI.
- **Small trusted base.** Redaction, safety, and detection — the parts that must
  not fail open — have no framework dependencies.
- **Swap-friendly.** Provider adapters, storage, and interfaces can change
  without touching detection logic.
