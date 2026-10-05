# Security policy

## Authorized use only

RedPrompt is for testing AI systems you **own or are explicitly permitted to
test**. By default it refuses to scan targets that are not marked authorized or
that resolve outside the loopback/allow-list (`safety.require_authorization`,
`safety.block_public_targets`). Do not use RedPrompt against systems you are not
authorized to assess.

## The lab is intentionally vulnerable

`redprompt-lab/` and `src/redprompt/lab/` are **insecure by design** and contain
only fake canaries. Run them locally only; never expose them or reuse the code.

## Reporting a vulnerability in RedPrompt

Please open a private security advisory on the repository (or email the
maintainer) with reproduction steps. Do not file public issues for security
reports. See `docs/threat-model.md` for RedPrompt's own security posture.

## Handling of sensitive data

- Target credentials are read from the environment by name and never stored.
- Evidence and logs are redacted before persistence; raw traffic is not retained
  unless `security.store_raw_traffic` is explicitly enabled.
- Treat `reports/` and the database as sensitive.
