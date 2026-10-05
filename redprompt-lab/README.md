# RedPrompt vulnerable lab

Five **intentionally insecure** local AI applications, used as reproducible test
targets for RedPrompt. They let RedPrompt demonstrate real security testing
without ever touching a third-party system.

> ⚠️ **INSECURE BY DESIGN.** These apps deliberately leak canaries, follow
> injected instructions, and mishandle input. They contain **no real secrets**
> (only clearly-fake `RP_*` / `sk-RPLAB...` lab canaries). Run them **locally
> only** — the compose file binds every port to `127.0.0.1`. Never expose them,
> and never reuse this code in production.

| App | Port | Class | Example finding |
|-----|-----:|-------|-----------------|
| chatbot  | 8001 | Vulnerable LLM chatbot     | prompt injection, system-prompt & secret disclosure |
| rag      | 8002 | Vulnerable RAG app         | cross-user retrieval, context leakage, indirect injection |
| agent    | 8003 | Vulnerable AI agent        | tool disclosure, unauthorized tool invocation, excessive agency |
| docagent | 8004 | Vulnerable document agent  | instruction injection via uploaded content |
| api      | 8005 | Vulnerable AI REST API     | missing auth, verbose errors, no input validation |

The apps simulate vulnerable behaviour **deterministically** (no real model), so
every scan produces the same findings.

## Run

```bash
docker compose -f redprompt-lab/docker-compose.yml up --build
# in another shell:
bash redprompt-lab/register-targets.sh
redprompt scan lab-agent
redprompt report lab-agent -f html
```

Without Docker you can run a single app directly:

```bash
pip install -e ".[lab]"
python -m redprompt.lab.server --app chatbot --port 8001
```

## How the tests reach them

The apps expose `POST /chat` (and `/`) accepting `{"message": "..."}` and return
`{"reply": "..."}`. RedPrompt's generic provider adapter speaks this shape. The
same apps are exercised in-process (via `httpx.ASGITransport`) by
`tests_offline/test_lab_e2e.py`, so the whole detection pipeline is verified
against them on every test run.
