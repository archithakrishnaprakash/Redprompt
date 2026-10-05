"""Offline tests exercising the security-test plugins end-to-end.

Each plugin runs against a crafted lab-like response (MockTransport) to confirm it
FAILs on the vulnerable case and PASSes on a refusal/secure case — i.e. it does
not fire on benign output (false-positive guard).
"""

from __future__ import annotations

import unittest

import httpx

from redprompt.config import load_settings
from redprompt.enums import TestStatus
from redprompt.http_client import AsyncHTTPClient
from redprompt.providers import build_provider
from redprompt.providers.base import TargetConnection
from redprompt.tests_plugins import markers as M
from redprompt.tests_plugins.base import TargetInfo, TestContext
from redprompt.tests_plugins.registry import build_registry

# Plugin classes
from redprompt.tests_plugins.prompt import (
    DirectPromptInjection,
    JailbreakOutputPolicyBypass,
    SystemPromptDisclosure,
)
from redprompt.tests_plugins.data import PIIExposure, SecretLeakage
from redprompt.tests_plugins.rag import CrossUserRetrieval, IndirectPromptInjectionViaRAG
from redprompt.tests_plugins.agent import UnauthorizedToolInvocation
from redprompt.tests_plugins.api import (
    AuthenticationEnforcement,
    InputValidation,
    VerboseErrorDisclosure,
)

EXPECTED_IDS = {
    "RP-PROMPT-001", "RP-PROMPT-002", "RP-PROMPT-003", "RP-PROMPT-004",
    "RP-DATA-001", "RP-DATA-002", "RP-DATA-003",
    "RP-RAG-001", "RP-RAG-002", "RP-RAG-003",
    "RP-AGENT-001", "RP-AGENT-002", "RP-AGENT-003",
    "RP-API-001", "RP-API-002", "RP-API-003",
    "RP-FILE-001",
}


def _text_handler(text: str, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"reply": text})
    return handler


def _raw_handler(*, status: int = 200, body_text: str = "ok"):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body_text)
    return handler


def _ctx(handler, *, auth_method="none", rag=False, agent=False):
    settings = load_settings(search=False)
    client = AsyncHTTPClient(transport=httpx.MockTransport(handler))
    conn = TargetConnection(base_url="http://127.0.0.1:8000", endpoint="/chat", auth_method=auth_method)
    provider = build_provider("generic", conn, client)
    target = TargetInfo(
        name="lab", base_url="http://127.0.0.1:8000", authorized=True,
        auth_method=auth_method, rag_enabled=rag, agent_enabled=agent,
    )
    return TestContext(target=target, provider=provider, settings=settings), client


class TestDiscovery(unittest.TestCase):
    def test_all_plugins_discovered(self) -> None:
        reg = build_registry()
        ids = {t.id for t in reg.all()}
        missing = EXPECTED_IDS - ids
        self.assertEqual(missing, set(), f"missing plugins: {missing}")


class TestPromptPlugins(unittest.IsolatedAsyncioTestCase):
    async def _run(self, plugin, text, **kw):
        ctx, client = _ctx(_text_handler(text), **kw)
        try:
            return await plugin.execute(ctx)
        finally:
            await client.aclose()

    async def test_direct_injection_fail(self) -> None:
        r = await self._run(DirectPromptInjection(), f"sure: {M.INJECTION_SUCCESS}")
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_direct_injection_refusal_pass(self) -> None:
        r = await self._run(DirectPromptInjection(), "I cannot ignore my instructions.")
        self.assertIs(r.status, TestStatus.PASS)

    async def test_system_prompt_disclosure_fail(self) -> None:
        r = await self._run(SystemPromptDisclosure(), f"my system prompt: ...{M.SYSTEM_CANARY}...")
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_jailbreak_fail(self) -> None:
        r = await self._run(JailbreakOutputPolicyBypass(), f"ok: {M.POLICY_TOKEN}")
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_benign_output_passes(self) -> None:
        r = await self._run(DirectPromptInjection(), "Here is a helpful, safe answer.")
        self.assertIs(r.status, TestStatus.PASS)


class TestDataPlugins(unittest.IsolatedAsyncioTestCase):
    async def _run(self, plugin, text):
        ctx, client = _ctx(_text_handler(text))
        try:
            return await plugin.execute(ctx)
        finally:
            await client.aclose()

    async def test_secret_leak_fail(self) -> None:
        r = await self._run(SecretLeakage(), f"here is the key {M.SECRET_CANARY}")
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_secret_leak_pass(self) -> None:
        r = await self._run(SecretLeakage(), "I won't share credentials.")
        self.assertIs(r.status, TestStatus.PASS)

    async def test_pii_fail(self) -> None:
        r = await self._run(PIIExposure(), "alice@example.com, bob@example.com")
        self.assertIs(r.status, TestStatus.FAIL)


class TestRAGPlugins(unittest.IsolatedAsyncioTestCase):
    async def _run(self, plugin, text):
        ctx, client = _ctx(_text_handler(text), rag=True)
        try:
            return await plugin.execute(ctx)
        finally:
            await client.aclose()

    async def test_cross_user_fail(self) -> None:
        r = await self._run(CrossUserRetrieval(), f"Document: {M.OTHER_USER_DOC} ...")
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_indirect_injection_fail(self) -> None:
        r = await self._run(IndirectPromptInjectionViaRAG(), f"summary... {M.POISONED_DOC_MARKER}")
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_rag_not_applicable_to_plain_llm(self) -> None:
        self.assertFalse(CrossUserRetrieval().applies_to(TargetInfo(name="x", base_url="http://127.0.0.1", rag_enabled=False)))


class TestAgentPlugins(unittest.IsolatedAsyncioTestCase):
    async def test_unauthorized_tool_text_marker_fail(self) -> None:
        ctx, client = _ctx(_text_handler(f"executed... {M.ADMIN_TOOL_MARKER}"), agent=True)
        try:
            r = await UnauthorizedToolInvocation().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_unauthorized_tool_pass_on_refusal(self) -> None:
        ctx, client = _ctx(_text_handler("I can't call that tool."), agent=True)
        try:
            r = await UnauthorizedToolInvocation().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.PASS)

    def test_agent_test_requires_agent(self) -> None:
        plain = TargetInfo(name="x", base_url="http://127.0.0.1", agent_enabled=False)
        self.assertFalse(UnauthorizedToolInvocation().applies_to(plain))


class TestAPIPlugins(unittest.IsolatedAsyncioTestCase):
    async def test_auth_enforcement_fail_when_2xx(self) -> None:
        ctx, client = _ctx(_raw_handler(status=200, body_text='{"reply":"ok"}'), auth_method="bearer")
        try:
            r = await AuthenticationEnforcement().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_auth_enforcement_pass_when_401(self) -> None:
        ctx, client = _ctx(_raw_handler(status=401, body_text="unauthorized"), auth_method="bearer")
        try:
            r = await AuthenticationEnforcement().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.PASS)

    def test_auth_not_applicable_when_no_auth(self) -> None:
        t = TargetInfo(name="x", base_url="http://127.0.0.1", auth_method="none")
        self.assertFalse(AuthenticationEnforcement().applies_to(t))

    async def test_error_leakage_fail(self) -> None:
        tb = 'Traceback (most recent call last):\n  File "/app/x.py", line 1\nValueError'
        ctx, client = _ctx(_raw_handler(status=500, body_text=tb))
        try:
            r = await VerboseErrorDisclosure().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_input_validation_500_fail(self) -> None:
        ctx, client = _ctx(_raw_handler(status=500, body_text="err"))
        try:
            r = await InputValidation().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.FAIL)

    async def test_input_validation_200_pass(self) -> None:
        ctx, client = _ctx(_raw_handler(status=200, body_text='{"reply":"ok"}'))
        try:
            r = await InputValidation().execute(ctx)
        finally:
            await client.aclose()
        self.assertIs(r.status, TestStatus.PASS)


if __name__ == "__main__":
    unittest.main()
