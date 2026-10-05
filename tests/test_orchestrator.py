"""End-to-end orchestrator tests (DB + MockTransport)."""

from __future__ import annotations

import httpx
import pytest

from redprompt.analysis.base import DetectionResult
from redprompt.core.context import AppContext
from redprompt.core.orchestrator import Orchestrator
from redprompt.db.models import Evidence, Finding, Scan, TestExecution
from redprompt.enums import Category, ScanStatus, Severity, TestStatus
from redprompt.exceptions import SafetyViolation
from redprompt.providers.base import ProviderRequest
from redprompt.targets.schemas import TargetCreate
from redprompt.targets.service import TargetService
from redprompt.tests_plugins.base import (
    SecurityTest,
    TestContext,
    TestResult,
    make_probe_record,
)
from redprompt.tests_plugins.registry import TestRegistry


class _PassTest(SecurityTest):
    id = "OR-PASS-1"
    name = "pass test"
    category = Category.PROMPT

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("hi"))
        det = DetectionResult.passed()
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


class _FailTest(SecurityTest):
    id = "OR-FAIL-1"
    name = "fail test"
    category = Category.PROMPT
    severity = Severity.HIGH

    def remediation(self) -> str:
        return "Do the secure thing."

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("leak?"))
        det = DetectionResult.failed(0.92, "leaked", indicators=["x"], evidence=[resp.text])
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


def _registry() -> TestRegistry:
    reg = TestRegistry()
    reg.register(_PassTest)
    reg.register(_FailTest)
    return reg


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "hello"})


def _add_target(ctx: AppContext, **kw) -> None:
    base = dict(name="lab", base_url="http://127.0.0.1:8000", provider="generic", authorized=True)
    base.update(kw)
    with ctx.session() as s:
        TargetService(s).add(TargetCreate(**base))


async def test_scan_creates_executions_findings_evidence(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    summary = await orch.run_scan("lab")

    assert summary.status == ScanStatus.COMPLETED.value
    assert summary.counts["total"] == 2
    assert summary.counts[TestStatus.PASS.value] == 1
    assert summary.counts[TestStatus.FAIL.value] == 1
    assert len(summary.findings) == 1
    assert summary.findings[0].finding_id.startswith("RP-PROMPT-")

    with ctx.session() as s:
        assert s.query(TestExecution).count() == 2
        finding = s.query(Finding).one()
        assert finding.severity is Severity.HIGH
        assert finding.remediation == "Do the secure thing."
        assert finding.status.value == "open"
        # evidence exists and is linked
        ev = s.query(Evidence).all()
        assert len(ev) == 2  # one probe per test
        assert any(e.finding_id == finding.id for e in ev)
        scan = s.query(Scan).one()
        assert scan.status is ScanStatus.COMPLETED
        assert scan.failed == 1


async def test_evidence_is_redacted(ctx: AppContext) -> None:
    _add_target(ctx)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"reply": "my token is sk-ABCDEFGHIJKLMNOPQR"})

    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(handler))
    await orch.run_scan("lab", test_ids=["OR-FAIL-1"])
    with ctx.session() as s:
        for e in s.query(Evidence).all():
            assert "sk-ABCDEFGHIJKLMNOPQR" not in str(e.response)


async def test_dry_run_no_findings(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    summary = await orch.run_scan("lab", dry_run=True)
    assert summary.counts[TestStatus.SKIPPED.value] == 2
    assert summary.findings == []
    with ctx.session() as s:
        assert s.query(Finding).count() == 0


async def test_unauthorized_target_aborts(ctx: AppContext) -> None:
    _add_target(ctx, name="ext", base_url="http://127.0.0.1:8000", authorized=False)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    with pytest.raises(SafetyViolation):
        await orch.run_scan("ext")
    with ctx.session() as s:
        scan = s.query(Scan).one()
        assert scan.status is ScanStatus.ABORTED


async def test_category_filter(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    summary = await orch.run_scan("lab", categories=["agent"])
    # no agent tests registered -> empty plan
    assert summary.counts["total"] == 0
