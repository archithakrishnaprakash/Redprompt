# Evidence model

Every finding is traceable to the exact request/response that produced it, stored
**redacted** and **tamper-evident**.

## What is captured

For each probe: the request (method, URL, redacted body), redacted headers, the
response (status, redacted text, tool calls), the extracted prompt context, the
detection result, evidence snippets, environment, and a content hash.

## Redaction before persistence

Redaction (`redprompt.redaction`) runs **before** anything is written:

- header/field values under sensitive keys (`authorization`, `api_key`, …) are masked;
- well-known secret shapes (bearer/OpenAI/AWS/GitHub/JWT/private-key) are removed
  from bodies and snippets;
- PII masking is available (off by default) for emails and card-like digits.

`security.store_raw_traffic=false` (default) means raw bodies are not retained by
the inspector at all.

## Integrity (tamper-evidence)

```
content_hash = SHA-256( canonical_json(
    {request, response, headers, detection_result, snippets} ) )
```

The hash is computed over the **redacted** content, so it covers exactly what is
stored. `verify_evidence()` recomputes and compares it; the CLI (`redprompt
evidence <finding>`) and dashboard show a per-record verified/HASH-MISMATCH badge.

## Storage

Evidence rows link to both the `test_execution` and the `finding`, carry the
`test_id`, `environment`, and optional `target_version`, and are queried via
`FindingService.evidence_for(finding_id)`.
