# Deployment

## Local install

```bash
pip install -e ".[dev,api,lab]"   # dev tools + API + lab
redprompt doctor                  # verify environment, DB, safety posture
alembic upgrade head              # apply migrations (or rely on quick-start create_all)
```

## Configuration

RedPrompt resolves settings with precedence
`CLI/overrides > REDPROMPT_* env > .redprompt.yml > defaults`. Copy the example
`.redprompt.yml` and adjust. Key sections: `safety`, `scan`, `risk`, `security`,
`output`, `logging`. See the file's comments.

Credentials for targets are read from the environment by variable **name**
(`--auth-env OPENAI_API_KEY`) and never stored.

## Database

SQLite by default (`sqlite:///redprompt.db`). For a shared deployment, point
`database_url` at PostgreSQL — the SQLAlchemy models and Alembic migrations are
portable (enums are stored as VARCHAR + CHECK).

## Docker

```bash
# App image (CLI/API)
docker build -t redprompt .
docker run --rm redprompt version
docker run --rm -p 127.0.0.1:8080:8080 redprompt serve --host 0.0.0.0 --token "$TOKEN"

# Vulnerable lab (loopback only)
docker compose -f redprompt-lab/docker-compose.yml up --build
```

## CI

- `.github/workflows/ci.yml` — lint, type-check, tests, SAST (bandit),
  dependency audit, docker build.
- `.github/workflows/redprompt-security.yml` — runs RedPrompt against the lab,
  uploads SARIF to GitHub code scanning, and fails the build on high-severity
  findings (`redprompt gate --fail-on high`).

## Serving safely

- Bind the API/dashboard to loopback, or set a `--token` for any other host.
- Keep the lab loopback-only; never expose it.
- Treat `reports/` and the database as sensitive (evidence is redacted but the
  system-under-test may still be identifiable).
