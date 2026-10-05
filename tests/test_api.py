"""REST API tests (FastAPI TestClient). Requires the 'api' extra."""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from redprompt.analysis.base import DetectionResult  # noqa: E402
from redprompt.api.app import create_app  # noqa: E402
from redprompt.core.context import AppContext  # noqa: E402
from redprompt.core.orchestrator import Orchestrator  # noqa: E402
from redprompt.enums import Category, Severity  # noqa: E402
from redprompt.providers.base import ProviderRequest  # noqa: E402
from redprompt.tests_plugins.base import SecurityTest, TestContext, TestResult, make_probe_record  # noqa: E402
from redprompt.tests_plugins.registry import TestRegistry  # noqa: E402


class _FailTest(SecurityTest):
    id = "AP-FAIL-1"
    name = "api finding"
    category = Category.DATA
    severity = Severity.HIGH

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("x"))
        det = DetectionResult.failed(0.9, "leak", evidence=[resp.text])
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


def _client(ctx: AppContext, token: str | None = None) -> TestClient:
    return TestClient(create_app(ctx, token=token))


def test_health(ctx: AppContext) -> None:
    r = _client(ctx).get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_dashboard_served(ctx: AppContext) -> None:
    r = _client(ctx).get("/")
    assert r.status_code == 200
    assert "RedPrompt" in r.text


def test_openapi_available(ctx: AppContext) -> None:
    r = _client(ctx).get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["title"] == "RedPrompt API"


def test_create_and_list_target(ctx: AppContext) -> None:
    c = _client(ctx)
    r = c.post("/api/targets", json={"name": "lab", "base_url": "http://127.0.0.1:8000", "authorized": True})
    assert r.status_code == 201
    assert c.get("/api/targets").json()[0]["name"] == "lab"


def test_auth_enforced(ctx: AppContext) -> None:
    c = _client(ctx, token="secret")
    assert c.get("/api/targets").status_code == 401
    assert c.get("/api/targets", headers={"Authorization": "Bearer secret"}).status_code == 200


def test_attack_surface_endpoint(ctx: AppContext) -> None:
    c = _client(ctx)
    c.post("/api/targets", json={"name": "lab", "base_url": "http://127.0.0.1:8000",
                                 "app_type": "agent", "agent_enabled": True, "authorized": True})
    g = c.get("/api/targets/lab/attack-surface").json()
    assert any(n["component"] == "agent" for n in g["nodes"])


async def test_scan_and_findings_via_api(ctx: AppContext) -> None:
    # Seed a target and run a scan through the orchestrator with a failing test,
    # then read findings back through the API.
    c = _client(ctx)
    c.post("/api/targets", json={"name": "lab", "base_url": "http://127.0.0.1:8000",
                                 "provider": "generic", "authorized": True})
    reg = TestRegistry()
    reg.register(_FailTest)
    await Orchestrator(
        ctx, reg, transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"reply": "leak"}))
    ).run_scan("lab")
    findings = c.get("/api/findings").json()
    assert len(findings) == 1
    fid = findings[0]["finding_id"]
    assert c.get(f"/api/findings/{fid}").status_code == 200
