"""Async HTTP client used to reach targets.

Wraps ``httpx.AsyncClient`` with the controls a security tester needs against a
system under test:

- **rate limiting** (min-interval between requests) so we never flood a target,
- **retry with exponential backoff** for transient network errors / 5xx / 429,
- a **hard request budget** per client (raises :class:`SafetyViolation` when
  exceeded) so a runaway test cannot hammer a target.

A custom ``transport`` can be injected (``httpx.MockTransport``) which makes the
whole client deterministically testable without any network.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from redprompt.exceptions import SafetyViolation

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass
class HTTPResult:
    status_code: int
    text: str
    headers: dict[str, str]
    latency_ms: int
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Any = None
    attempts: int = 1

    def json(self) -> Any:
        import json as _json

        return _json.loads(self.text) if self.text else None


class RateLimiter:
    """Simple async min-interval rate limiter (requests per second)."""

    def __init__(self, rate_per_second: float) -> None:
        self._min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


class AsyncHTTPClient:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        connect_timeout: float = 10.0,
        retry_attempts: int = 3,
        backoff_seconds: float = 0.5,
        rate_limit_per_second: float = 5.0,
        max_requests: int = 500,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
        follow_redirects: bool = False,
        inspector: Any = None,
    ) -> None:
        self._retry_attempts = max(1, retry_attempts)
        self._backoff = backoff_seconds
        self._max_requests = max_requests
        self._request_count = 0
        self._inspector = inspector
        self._rate_limiter = RateLimiter(rate_limit_per_second)
        timeout_cfg = httpx.Timeout(timeout, connect=connect_timeout)
        self._client = httpx.AsyncClient(
            timeout=timeout_cfg,
            transport=transport,
            follow_redirects=follow_redirects,
        )

    @property
    def request_count(self) -> int:
        return self._request_count

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: Any = None,
        content: str | bytes | None = None,
    ) -> HTTPResult:
        if self._request_count >= self._max_requests:
            raise SafetyViolation(
                f"request budget exhausted ({self._max_requests}); refusing to send more "
                "traffic to the target"
            )

        for attempt in range(1, self._retry_attempts + 1):
            await self._rate_limiter.acquire()
            self._request_count += 1
            start = time.monotonic()
            try:
                response = await self._client.request(
                    method, url, headers=headers, json=json, content=content
                )
            except httpx.TransportError:
                if attempt < self._retry_attempts:
                    await self._sleep_backoff(attempt)
                    continue
                raise
            latency_ms = int((time.monotonic() - start) * 1000)

            if response.status_code in RETRY_STATUS and attempt < self._retry_attempts:
                await self._sleep_backoff(attempt)
                continue

            result = HTTPResult(
                status_code=response.status_code,
                text=response.text,
                headers=dict(response.headers),
                latency_ms=latency_ms,
                url=str(response.request.url),
                request_headers=dict(response.request.headers),
                request_body=json if json is not None else content,
                attempts=attempt,
            )
            if self._inspector is not None:
                self._inspector.capture(result)
            return result

        # Unreachable: the final attempt always returns (retryable status included)
        # or re-raises a TransportError inside the loop.
        raise RuntimeError("http retry loop exited unexpectedly")  # pragma: no cover

    async def _sleep_backoff(self, attempt: int) -> None:
        if self._backoff > 0:
            await asyncio.sleep(self._backoff * (2 ** (attempt - 1)))

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncHTTPClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
