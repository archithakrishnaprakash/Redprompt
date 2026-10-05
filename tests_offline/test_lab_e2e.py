"""End-to-end: run RedPrompt's real plugins against the vulnerable lab in-process.

Uses httpx.ASGITransport so RedPrompt talks to each Starlette lab app directly —
no network, no database — exercising the full provider → engine → detector path
against genuinely (intentionally) vulnerable targets.
"""

from __future__ import annotations

import unittest

import httpx

from redprompt.config import load_settings
from redprompt.core.engine import ScanEngine
from redprompt.enums import TestStatus
from redprompt.http_client import AsyncHTTPClient
from redprompt.lab.apps import (
    create_agent_app,
    create_api_app,
    create_chatbot_app,
    create_docagent_app,
    create_rag_app,
)
from redprompt.providers import build_provider
from redprompt.providers.base import TargetConnection
from redprompt.tests_plugins.base import TargetInfo
from redprompt.tests_plugins.registry import build_registry


async def _scan_app(app, target: TargetInfo, *, endpoint="/chat", auth_method="none") -> dict[str, str]:
    transport = httpx.ASGITransport(app=app)
    client = AsyncHTTPClient(transport=transport)
    conn = TargetConnection(base_url=target.base_url, endpoint=endpoint, auth_method=auth_method)
    provider = build_provider("generic", conn, client)
    engine = ScanEngine(load_settings(search=False))
    plan = build_registry().for_target(target)
    try:
        result = await engine.run(target, provider, plan)
    finally:
        await client.aclose()
    return {r.test_id: r.status.value for r in result.results}


def _fail(statuses: dict[str, str], test_id: str) -> bool:
    return statuses.get(test_id) == TestStatus.FAIL.value


class TestLabChatbot(unittest.IsolatedAsyncioTestCase):
    async def test_chatbot_vulnerabilities(self) -> None:
        target = TargetInfo(name="chatbot", base_url="http://127.0.0.1:8001", app_type="llm", authorized=True)
        s = await _scan_app(create_chatbot_app(), target)
        self.assertTrue(_fail(s, "RP-PROMPT-001"), "direct injection should fail")
        self.assertTrue(_fail(s, "RP-PROMPT-003"), "system prompt disclosure should fail")
        self.assertTrue(_fail(s, "RP-PROMPT-004"), "jailbreak should fail")
        self.assertTrue(_fail(s, "RP-DATA-001"), "secret leakage should fail")
        self.assertTrue(_fail(s, "RP-DATA-002"), "PII exposure should fail")


class TestLabRAG(unittest.IsolatedAsyncioTestCase):
    async def test_rag_vulnerabilities(self) -> None:
        target = TargetInfo(name="rag", base_url="http://127.0.0.1:8002", app_type="rag",
                            rag_enabled=True, authorized=True)
        s = await _scan_app(create_rag_app(), target)
        self.assertTrue(_fail(s, "RP-RAG-001"), "cross-user retrieval should fail")
        self.assertTrue(_fail(s, "RP-RAG-002"), "context leakage should fail")
        self.assertTrue(_fail(s, "RP-RAG-003"), "indirect injection should fail")
        # Honest: the RAG app is not prompt-injectable, so prompt tests should pass.
        self.assertEqual(s.get("RP-PROMPT-001"), TestStatus.PASS.value)


class TestLabAgent(unittest.IsolatedAsyncioTestCase):
    async def test_agent_vulnerabilities(self) -> None:
        target = TargetInfo(name="agent", base_url="http://127.0.0.1:8003", app_type="agent",
                            agent_enabled=True, tools=["search", "admin_delete_all"], authorized=True)
        s = await _scan_app(create_agent_app(), target)
        self.assertTrue(_fail(s, "RP-AGENT-001"), "tool inventory disclosure should fail")
        self.assertTrue(_fail(s, "RP-AGENT-002"), "unauthorized tool invocation should fail")
        self.assertTrue(_fail(s, "RP-AGENT-003"), "excessive agency should fail")


class TestLabDocAgent(unittest.IsolatedAsyncioTestCase):
    async def test_docagent_file_injection(self) -> None:
        target = TargetInfo(name="docagent", base_url="http://127.0.0.1:8004", app_type="document",
                            file_upload=True, authorized=True)
        s = await _scan_app(create_docagent_app(), target)
        self.assertTrue(_fail(s, "RP-FILE-001"), "document instruction injection should fail")


class TestLabAPI(unittest.IsolatedAsyncioTestCase):
    async def test_api_vulnerabilities(self) -> None:
        target = TargetInfo(name="api", base_url="http://127.0.0.1:8005", app_type="api",
                            auth_method="bearer", authorized=True)
        s = await _scan_app(create_api_app(), target, endpoint="/", auth_method="bearer")
        self.assertTrue(_fail(s, "RP-API-001"), "auth enforcement should fail")
        self.assertTrue(_fail(s, "RP-API-002"), "verbose error disclosure should fail")
        self.assertTrue(_fail(s, "RP-API-003"), "input validation should fail")


if __name__ == "__main__":
    unittest.main()
