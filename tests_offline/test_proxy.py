"""Offline tests for the traffic inspector (redaction, retention, body store)."""

from __future__ import annotations

import unittest

import httpx

from redprompt.http_client import AsyncHTTPClient
from redprompt.proxy import TrafficInspector


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "token sk-ABCDEFGHIJKLMNOPQR"})


class TestInspectorCapture(unittest.IsolatedAsyncioTestCase):
    async def _run(self, inspector: TrafficInspector, n: int = 1) -> None:
        async with AsyncHTTPClient(transport=httpx.MockTransport(_handler), inspector=inspector) as c:
            for _ in range(n):
                await c.request(
                    "POST", "http://127.0.0.1:8000/chat",
                    headers={"Authorization": "Bearer sk-secret000000000"},
                    json={"message": "hi"},
                )

    async def test_capture_records(self) -> None:
        insp = TrafficInspector()
        await self._run(insp)
        self.assertEqual(len(insp), 1)
        rec = insp.records()[0]
        self.assertEqual(rec.status_code, 200)

    async def test_headers_and_body_redacted(self) -> None:
        insp = TrafficInspector(redact=True, store_body=True)
        await self._run(insp)
        rec = insp.records()[0]
        self.assertEqual(rec.request_headers.get("authorization"), "«redacted»")
        self.assertNotIn("sk-ABCDEFGHIJKLMNOPQR", str(rec.response_body))

    async def test_body_not_retained_when_disabled(self) -> None:
        insp = TrafficInspector(store_body=False)
        await self._run(insp)
        rec = insp.records()[0]
        self.assertEqual(rec.request_body, "«body-not-retained»")
        self.assertEqual(rec.response_body, "«body-not-retained»")

    async def test_retention_bounds_records(self) -> None:
        insp = TrafficInspector(max_records=3)
        await self._run(insp, n=5)
        self.assertEqual(len(insp), 3)

    async def test_summary(self) -> None:
        insp = TrafficInspector()
        await self._run(insp, n=2)
        summary = insp.summary()
        self.assertEqual(summary["count"], 2)
        self.assertIn(200, summary["status_codes"])

    def test_empty_summary(self) -> None:
        self.assertEqual(TrafficInspector().summary(), {"count": 0})


if __name__ == "__main__":
    unittest.main()
