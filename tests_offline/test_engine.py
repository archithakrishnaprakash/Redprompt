"""Offline async tests for the pure scan engine (fake tests + MockTransport)."""

from __future__ import annotations

import unittest

import httpx

from redprompt.analysis.base import DetectionResult
from redprompt.config import load_settings
from redprompt.core.engine import ScanEngine
from redprompt.enums import Category, Severity, TestStatus
from redprompt.exceptions import SafetyViolation
from redprompt.http_client import AsyncHTTPClient
from redprompt.providers import build_provider
from redprompt.providers.base import ProviderRequest, TargetConnection
from redprompt.tests_plugins.base import (
    SecurityTest,
    TargetInfo,
    TestContext,
    TestResult,
    make_probe_record,
)


class _PassTest(SecurityTest):
    id = "EN-PASS-1"
    name = "pass"
    category = Category.PROMPT

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("hi"))
        det = DetectionResult.passed()
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


class _FailTest(SecurityTest):
    id = "EN-FAIL-1"
    name = "fail"
    category = Category.PROMPT
    severity = Severity.HIGH

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("leak?"))
        det = DetectionResult.failed(0.9, "leaked", indicators=["secret"], evidence=[resp.text])
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


class _AgentOnly(SecurityTest):
    id = "EN-AGENT-1"
    name = "agent-only"
    category = Category.AGENT

    def applies_to(self, target: TargetInfo) -> bool:
        return target.agent_enabled

    async def execute(self, ctx: TestContext) -> TestResult:  # pragma: no cover
        return self.result(DetectionResult.passed())


class _BoomTest(SecurityTest):
    id = "EN-ERR-1"
    name = "boom"
    category = Category.PROMPT

    async def execute(self, ctx: TestContext) -> TestResult:
        raise RuntimeError("kaboom")


def _settings():
    return load_settings(search=False)


def _target(**kw) -> TargetInfo:
    base = dict(name="lab", base_url="http://127.0.0.1:8000", authorized=True)
    base.update(kw)
    return TargetInfo(**base)


def _provider_and_client(handler):
    client = AsyncHTTPClient(transport=httpx.MockTransport(handler))
    conn = TargetConnection(base_url="http://127.0.0.1:8000", endpoint="/chat")
    provider = build_provider("generic", conn, client)
    return provider, client


def _ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "hello"})


class TestScanEngine(unittest.IsolatedAsyncioTestCase):
    async def test_pass_and_fail_counts(self) -> None:
        provider, client = _provider_and_client(_ok_handler)
        engine = ScanEngine(_settings())
        try:
            result = await engine.run(_target(), provider, [_PassTest(), _FailTest()])
        finally:
            await client.aclose()
        self.assertEqual(result.counts["total"], 2)
        self.assertEqual(result.counts[TestStatus.PASS.value], 1)
        self.assertEqual(result.counts[TestStatus.FAIL.value], 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)

    async def test_dry_run_sends_no_traffic(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json={"reply": "x"})

        provider, client = _provider_and_client(handler)
        engine = ScanEngine(_settings())
        try:
            result = await engine.run(_target(), provider, [_PassTest(), _FailTest()], dry_run=True)
        finally:
            await client.aclose()
        self.assertEqual(calls["n"], 0)
        self.assertEqual(result.counts[TestStatus.SKIPPED.value], 2)

    async def test_unauthorized_target_blocked(self) -> None:
        provider, client = _provider_and_client(_ok_handler)
        engine = ScanEngine(_settings())
        try:
            with self.assertRaises(SafetyViolation):
                await engine.run(_target(authorized=False), provider, [_PassTest()])
        finally:
            await client.aclose()

    async def test_public_target_blocked(self) -> None:
        provider, client = _provider_and_client(_ok_handler)
        engine = ScanEngine(_settings())
        try:
            with self.assertRaises(SafetyViolation):
                await engine.run(
                    _target(base_url="https://api.example.com", authorized=True),
                    provider,
                    [_PassTest()],
                )
        finally:
            await client.aclose()

    async def test_not_applicable_skipped(self) -> None:
        provider, client = _provider_and_client(_ok_handler)
        engine = ScanEngine(_settings())
        try:
            result = await engine.run(_target(agent_enabled=False), provider, [_AgentOnly()])
        finally:
            await client.aclose()
        self.assertEqual(result.counts[TestStatus.SKIPPED.value], 1)

    async def test_broken_test_is_error(self) -> None:
        provider, client = _provider_and_client(_ok_handler)
        engine = ScanEngine(_settings())
        try:
            result = await engine.run(_target(), provider, [_BoomTest()])
        finally:
            await client.aclose()
        self.assertEqual(result.counts[TestStatus.ERROR.value], 1)
        self.assertIn("kaboom", result.results[0].reason)

    async def test_durations_recorded(self) -> None:
        provider, client = _provider_and_client(_ok_handler)
        engine = ScanEngine(_settings())
        try:
            result = await engine.run(_target(), provider, [_PassTest()])
        finally:
            await client.aclose()
        self.assertGreaterEqual(result.results[0].duration_ms, 0)


if __name__ == "__main__":
    unittest.main()
