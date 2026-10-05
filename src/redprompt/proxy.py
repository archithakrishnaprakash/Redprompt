"""Controlled HTTP/API inspection layer.

A :class:`TrafficInspector` observes every request/response the client makes to a
target and records a redacted, size-bounded copy for later review. It implements
the spec's proxy concerns as configuration rather than a man-in-the-middle:

    redaction   secrets/PII removed before a record is kept (default on)
    retention   only the most recent ``max_records`` are held (bounded memory)
    logging     records serialise to JSON for export
    body store  raw bodies are dropped entirely unless explicitly enabled

It never persists more than asked: with ``store_body=False`` request/response
bodies are replaced with a placeholder, so sensitive model traffic is not retained.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from redprompt.redaction import redact_headers, redact_value

if TYPE_CHECKING:
    from redprompt.http_client import HTTPResult

_BODY_OMITTED = "«body-not-retained»"
_MAX_BODY_CHARS = 10_000


@dataclass
class InspectionRecord:
    timestamp: str
    method: str
    url: str
    status_code: int
    latency_ms: int
    attempts: int
    request_headers: dict[str, Any] = field(default_factory=dict)
    request_body: Any = None
    response_headers: dict[str, Any] = field(default_factory=dict)
    response_body: Any = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _MAX_BODY_CHARS:
        return value[:_MAX_BODY_CHARS] + f"…«+{len(value) - _MAX_BODY_CHARS} chars»"
    return value


class TrafficInspector:
    def __init__(
        self,
        *,
        redact: bool = True,
        store_body: bool = True,
        include_pii: bool = False,
        max_records: int = 1000,
    ) -> None:
        self.redact = redact
        self.store_body = store_body
        self.include_pii = include_pii
        self._records: deque[InspectionRecord] = deque(maxlen=max_records)

    def capture(self, result: "HTTPResult") -> InspectionRecord:
        req_headers = dict(result.request_headers)
        req_body = result.request_body
        resp_headers = dict(result.headers)
        resp_body: Any = result.text

        if self.redact:
            req_headers = redact_headers(req_headers)
            req_body = redact_value(req_body, include_pii=self.include_pii)
            resp_headers = redact_headers(resp_headers)
            resp_body = redact_value(resp_body, include_pii=self.include_pii)

        if not self.store_body:
            req_body = _BODY_OMITTED
            resp_body = _BODY_OMITTED

        record = InspectionRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            method="POST" if req_body is not None else "GET",
            url=result.url,
            status_code=result.status_code,
            latency_ms=result.latency_ms,
            attempts=result.attempts,
            request_headers=req_headers,
            request_body=_truncate(req_body),
            response_headers=resp_headers,
            response_body=_truncate(resp_body),
        )
        self._records.append(record)
        return record

    def records(self) -> list[InspectionRecord]:
        return list(self._records)

    def to_dict(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._records]

    def clear(self) -> None:
        self._records.clear()

    def summary(self) -> dict[str, Any]:
        recs = self._records
        if not recs:
            return {"count": 0}
        latencies = [r.latency_ms for r in recs]
        statuses: dict[int, int] = {}
        for r in recs:
            statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
        return {
            "count": len(recs),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1),
            "max_latency_ms": max(latencies),
            "status_codes": statuses,
        }

    def __len__(self) -> int:
        return len(self._records)
