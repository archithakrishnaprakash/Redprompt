"""Evidence assembly — redaction + tamper-evident hashing (pure).

Turns a captured :class:`ProbeRecord` into a persistable, redacted evidence
payload with a content hash over the redacted content. Redaction happens *before*
hashing and persistence, so secrets never reach the database and the hash covers
exactly what is stored (making later tampering detectable).

This module is dependency-free (stdlib + redaction) and fully unit-testable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from redprompt.redaction import redact_headers, redact_value
from redprompt.tests_plugins.base import ProbeRecord


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def build_evidence_payload(
    probe: ProbeRecord,
    *,
    test_id: str,
    environment: str = "local",
    target_version: str | None = None,
    redact_secrets: bool = True,
    include_pii: bool = False,
) -> dict[str, Any]:
    """Return a redacted, hashed evidence payload (ORM-field shaped, no FKs)."""
    req = dict(probe.request)
    resp = dict(probe.response)

    raw_headers = req.get("headers", {}) or {}
    body = req.get("body")

    if redact_secrets:
        headers = redact_headers(raw_headers)
        request_body = redact_value(body, include_pii=include_pii)
        response = redact_value(resp, include_pii=include_pii)
        snippets = [
            redact_value(s, include_pii=include_pii) for s in probe.detection.get("evidence", [])
        ]
    else:
        headers = dict(raw_headers)
        request_body = body
        response = resp
        snippets = list(probe.detection.get("evidence", []))

    request = {
        "method": req.get("method"),
        "url": req.get("url"),
        "body": request_body,
    }
    tool_invocation = resp.get("tool_calls") or None

    payload: dict[str, Any] = {
        "test_id": test_id,
        "request": request,
        "response": response,
        "headers": headers,
        "prompt_context": _extract_prompt(request_body),
        "tool_invocation": tool_invocation,
        "detection_result": probe.detection,
        "snippets": snippets,
        "environment": environment,
        "target_version": target_version,
    }
    payload["content_hash"] = content_hash(
        {k: payload[k] for k in ("request", "response", "headers", "detection_result", "snippets")}
    )
    return payload


def verify_evidence(payload: dict[str, Any]) -> bool:
    """Recompute the hash over the stored fields and compare (integrity check)."""
    expected = content_hash(
        {k: payload.get(k) for k in ("request", "response", "headers", "detection_result", "snippets")}
    )
    return expected == payload.get("content_hash")


def _extract_prompt(body: Any) -> str | None:
    """Best-effort human-readable prompt text from a request body (redacted already)."""
    if isinstance(body, dict):
        for key in ("messages", "message", "prompt", "input", "q"):
            if key in body:
                value = body[key]
                if isinstance(value, list):
                    return "\n".join(
                        f"{m.get('role', '?')}: {m.get('content', '')}"
                        for m in value
                        if isinstance(m, dict)
                    )
                return str(value)
    if isinstance(body, str):
        return body
    return None
