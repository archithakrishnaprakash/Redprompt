# Threat model (RedPrompt itself)

RedPrompt is a security tool, so it must be secure. This is a STRIDE threat model
for RedPrompt and its lab. It is deliberately honest about residual risk.

## Assets

- **Target credentials** (API keys/tokens). RedPrompt stores only the *name* of
  the environment variable holding a credential, never the value.
- **Evidence** (captured request/response traffic). May contain sensitive data
  from the system under test.
- **Findings / assessment results** and their integrity.
- **The vulnerable lab** — intentionally insecure; must never be exposed.
- **The dashboard / API** and the data behind it.

## Trust boundaries

1. Operator ↔ RedPrompt CLI/API.
2. RedPrompt ↔ target application (untrusted responses).
3. RedPrompt ↔ its database and report files.
4. Host network ↔ the vulnerable lab (must stay loopback).

## Threat actors

- A malicious/compromised **target** returning hostile content (prompt-injection
  payloads, huge bodies, secrets) in responses RedPrompt parses and stores.
- An operator who **misconfigures scope** and points RedPrompt at a system they
  are not authorized to test.
- A network attacker who can reach an exposed **lab** or **dashboard**.

## STRIDE

| Threat | Scenario | Control |
|--------|----------|---------|
| **S**poofing | Unauthenticated access to the dashboard/API | Bearer-token auth (`--token`/env); non-loopback bind refused without a token |
| **T**ampering | Evidence altered after capture | SHA-256 `content_hash` over stored fields; `verify_evidence` integrity check surfaced in CLI/UI |
| **R**epudiation | "Which scan produced this finding?" | Every finding links to a scan, execution, and hashed evidence; structured logs carry `scan_id`/`test_id` |
| **I**nformation disclosure | Secrets/PII from target traffic leak into logs, evidence, reports | Central `redaction` core applied to logs, evidence, and inspector *before* persistence; `store_raw_traffic=false` by default |
| **D**enial of service | RedPrompt floods a target; or a huge target response exhausts memory | Rate limiter, per-target request budget (`SafetyViolation` when exceeded), response-body truncation in the inspector |
| **E**levation of privilege | Testing an out-of-scope/unauthorized target | `require_authorization` + `block_public_targets` + loopback allow-list; `SafetyViolation` is never swallowed; dry-run mode |

## RedPrompt's own hardening

- No `eval`/`exec`/`os.system`/`shell=True`; `yaml.safe_load` only.
- Pydantic-validated configuration and inputs; typed code.
- Secrets resolved from the environment at call time, never stored in the DB.
- Non-root container images; loopback-only lab ports; dependency pinning +
  `bandit`/`pip-audit` in CI.
- Errors surfaced, not hidden; heuristic detections labelled; no fabricated
  findings.

## Lab security assumptions

The lab apps are **insecure by design**. They:
- contain only fake `RP_*` / `sk-RPLAB...` canaries (no real secrets);
- are bound to `127.0.0.1` by the compose file;
- must never be deployed to a shared/public network or reused in production.

## Residual risks (accepted)

- Redaction is pattern-based and can miss novel secret shapes; operators should
  treat evidence as sensitive regardless.
- Heuristic detectors can produce false positives/negatives; findings are
  evidence-backed to support human triage, not to replace it.
- The dashboard's single shared token is coarse-grained (no per-user RBAC).
