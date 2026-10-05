"""Offline async tests for the HTTP client (deterministic via httpx.MockTransport)."""

from __future__ import annotations

import unittest

import httpx

from redprompt.exceptions import SafetyViolation
from redprompt.http_client import AsyncHTTPClient
from redprompt.providers import build_provider
from redprompt.providers.base import ProviderRequest, TargetConnection


class TestAsyncHTTPClient(unittest.IsolatedAsyncioTestCase):
    async def test_basic_request(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True})

        async with AsyncHTTPClient(transport=httpx.MockTransport(handler)) as client:
            result = await client.request("GET", "http://127.0.0.1:8000/x")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {"ok": True})
        self.assertEqual(result.attempts, 1)

    async def test_retry_on_503_then_success(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(503, text="busy")
            return httpx.Response(200, json={"ok": True})

        async with AsyncHTTPClient(
            transport=httpx.MockTransport(handler), backoff_seconds=0, retry_attempts=3
        ) as client:
            result = await client.request("POST", "http://127.0.0.1:8000/x", json={"a": 1})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(calls["n"], 2)

    async def test_retry_exhausted_returns_last(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="still busy")

        async with AsyncHTTPClient(
            transport=httpx.MockTransport(handler), backoff_seconds=0, retry_attempts=2
        ) as client:
            result = await client.request("GET", "http://127.0.0.1:8000/x")
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.attempts, 2)

    async def test_retry_on_transport_error(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.ConnectError("boom")
            return httpx.Response(200, json={"ok": True})

        async with AsyncHTTPClient(
            transport=httpx.MockTransport(handler), backoff_seconds=0, retry_attempts=3
        ) as client:
            result = await client.request("GET", "http://127.0.0.1:8000/x")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(calls["n"], 2)

    async def test_request_budget_enforced(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True})

        async with AsyncHTTPClient(
            transport=httpx.MockTransport(handler), max_requests=2
        ) as client:
            await client.request("GET", "http://127.0.0.1:8000/x")
            await client.request("GET", "http://127.0.0.1:8000/x")
            with self.assertRaises(SafetyViolation):
                await client.request("GET", "http://127.0.0.1:8000/x")


class TestProviderGenerateEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def test_openai_generate(self) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            captured["url"] = str(request.url)
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"model": "gpt", "choices": [{"message": {"content": "pong"}, "finish_reason": "stop"}]},
            )

        conn = TargetConnection(base_url="http://127.0.0.1:8000", model="gpt")
        async with AsyncHTTPClient(transport=httpx.MockTransport(handler)) as client:
            provider = build_provider("openai", conn, client)
            resp = await provider.generate(ProviderRequest.from_prompt("ping"))

        self.assertTrue(resp.ok)
        self.assertEqual(resp.text, "pong")
        self.assertEqual(resp.finish_reason, "stop")
        self.assertEqual(captured["url"], "http://127.0.0.1:8000/v1/chat/completions")
        self.assertEqual(captured["body"]["messages"][-1]["content"], "ping")

    async def test_generic_generate(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"reply": "hi from app"})

        conn = TargetConnection(base_url="http://127.0.0.1:8001", endpoint="/chat")
        async with AsyncHTTPClient(transport=httpx.MockTransport(handler)) as client:
            provider = build_provider("generic", conn, client)
            resp = await provider.generate(ProviderRequest.from_prompt("hello"))
        self.assertEqual(resp.text, "hi from app")


if __name__ == "__main__":
    unittest.main()
