# REST API

The API (FastAPI) exposes RedPrompt for automation. Start it with:

```bash
pip install -e ".[api]"
redprompt serve --host 127.0.0.1 --port 8080 --token "$REDPROMPT_DASHBOARD_TOKEN"
```

- Dashboard: `GET /`
- OpenAPI schema: `GET /openapi.json` · Swagger UI: `GET /docs`
- Auth: when a token is set, every `/api/*` route requires
  `Authorization: Bearer <token>`. A non-loopback bind without a token is refused.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | version + counts |
| GET | `/api/targets` | list targets |
| POST | `/api/targets` | register a target (body: `TargetCreate`) |
| GET | `/api/targets/{id}` | target detail |
| GET | `/api/targets/{id}/attack-surface` | attack-surface graph |
| POST | `/api/scans` | run a scan (body: `{target, categories?, test_ids?, dry_run?, workers?}`) |
| GET | `/api/scans` · `/api/scans/{uuid}` | list / detail |
| GET | `/api/findings` `?severity=&status_=` | list findings |
| GET | `/api/findings/{id}` | finding detail (incl. risk breakdown) |
| POST | `/api/findings/{id}/retest` | retest a finding |
| GET | `/api/tests` | test library |
| GET | `/api/reports/{scan_uuid}` | full JSON report |

## Example

```bash
curl -s localhost:8080/api/health
curl -s -X POST localhost:8080/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":"lab-agent"}'
curl -s 'localhost:8080/api/findings?severity=critical'
```
