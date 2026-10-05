# Offline test harness

These `unittest`-based tests cover RedPrompt's **pure-Python domain core**
(redaction, enums, configuration, detection/analysis, risk scoring, evidence
integrity, SARIF) — the security-critical logic that has no heavy third-party
dependencies. They run with only the standard library plus `pydantic` and
`pyyaml`, so they execute in constrained environments where the full stack
(SQLAlchemy, FastAPI, Typer, pytest) cannot be installed.

```bash
python -m unittest discover -s tests_offline -v
```

The canonical, full-coverage suite lives in `tests/` and runs under `pytest`
in CI and on a normal developer machine. Every offline test here also passes
under `pytest` — this harness is an additive way to verify the domain core
without the full toolchain, not a replacement for it.
