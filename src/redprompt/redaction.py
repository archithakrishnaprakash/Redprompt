"""Secret and PII redaction — pure standard library, no third-party imports.

This module is deliberately dependency-free so it can be exercised anywhere
(including constrained environments) and so the security-critical redaction logic
has the smallest possible trusted computing base. It is used by logging, the
inspection proxy, and the evidence store, guaranteeing a single consistent
definition of "what must never be persisted or printed".
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTION = "«redacted»"

# Well-known secret shapes. Kept conservative to minimise false positives while
# reliably catching credentials that commonly leak into logs and evidence.
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),                       # OpenAI-style
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),             # Slack-style
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),                # GitHub tokens
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),  # JWT
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

# Light PII shapes. Emails and long digit runs (card-like) are masked in stored
# evidence by default; this is heuristic and documented as such.
PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),                    # card-like digit runs
)

# Dict keys whose *values* are always sensitive regardless of content.
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "x-api-key",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "cookie",
        "set-cookie",
    }
)


def redact_text(value: str, *, include_pii: bool = False) -> str:
    """Redact well-known secret shapes (and optionally PII) from a string."""
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTION, redacted)
    if include_pii:
        for pattern in PII_PATTERNS:
            redacted = pattern.sub(REDACTION, redacted)
    return redacted


def redact_value(value: Any, *, include_pii: bool = False, _key: str | None = None) -> Any:
    """Recursively redact a JSON-like structure.

    - values under sensitive keys are fully masked
    - strings are pattern-redacted
    - mappings and sequences are processed element-wise
    """
    if _key is not None and _key.lower() in SENSITIVE_KEYS:
        return REDACTION
    if isinstance(value, str):
        return redact_text(value, include_pii=include_pii)
    if isinstance(value, Mapping):
        return {k: redact_value(v, include_pii=include_pii, _key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v, include_pii=include_pii) for v in value]
    return value


def redact_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    """Redact an HTTP header mapping (case-insensitive sensitive-key match)."""
    return {k: redact_value(v, _key=str(k)) for k, v in headers.items()}
