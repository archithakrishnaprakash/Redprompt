# Contributing

Thanks for your interest in RedPrompt.

## Setup

```bash
pip install -e ".[dev,api,lab]"
pre-commit install
```

## Quality gates (run before pushing)

```bash
make lint         # ruff
make format       # black + ruff --fix
make type         # mypy
make test         # pytest (full stack)
make test-offline # stdlib unittest core harness
```

CI runs all of the above plus `bandit` and `pip-audit`.

## Adding a security test

See `docs/plugin-development.md`. Every new test must ship with an offline test
that asserts **both** the vulnerable (FAIL) and refusal/benign (PASS) cases, and
should map to an OWASP LLM risk in `docs/owasp-mapping.md`.

## Principles

- Never fabricate findings or hardcode scan results.
- Label heuristic/experimental detection honestly.
- Keep the domain core dependency-light and testable.
- Only target authorized systems; keep the lab loopback-only.
- Type-hint everything; keep modules small.

## Commit style

Conventional, imperative subject lines. Keep PRs focused; update docs and tests
alongside code.
