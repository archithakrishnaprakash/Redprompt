"""Tests for the DB report builder and file generation."""

from __future__ import annotations

from pathlib import Path

import httpx

from redprompt.analysis.base import DetectionResult
from redprompt.core.context import AppContext
from redprompt.core.orchestrator import Orchestrator
from redprompt.enums import Category, Severity
from redprompt.providers.base import ProviderRequest
from redprompt.reporting.builder import ReportBuilder
from redprompt.reporting.gate import evaluate_gate
from redprompt.reporting.generate import generate_reports
from redprompt.targets.schemas import TargetCreate
from redprompt.targets.service import TargetService
from redprompt.tests_plugins.base import SecurityTest, TestContext, TestResult, make_probe_record
from redprompt.tests_plugins.registry import TestRegistry


class _FailTest(SecurityTest):
    id = "RB-FAIL-1"
    name = "reportable finding"
    category = Category.DATA
    severity = Severity.CRITICAL

    def remediation(self) -> str:
        return "Fix it."

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("x"))
        det = DetectionResult.failed(0.95, "leak", evidence=[resp.text])
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


def _registry() -> TestRegistry:
    reg = TestRegistry()
    reg.register(_FailTest)
    return reg


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "sk-RPLABSECRET000000000000"})


async def _scan(ctx: AppContext) -> str:
    with ctx.session() as s:
        TargetService(s).add(
            TargetCreate(name="lab", base_url="http://127.0.0.1:8000", provider="generic", authorized=True)
        )
    summary = await Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler)).run_scan("lab")
    return summary.scan_uuid


async def test_builder_assembles_report(ctx: AppContext) -> None:
    scan_uuid = await _scan(ctx)
    with ctx.session() as s:
        data = ReportBuilder(s).for_scan(scan_uuid)
    assert data.target["name"] == "lab"
    assert len(data.findings) == 1
    f = data.findings[0]
    assert f.evidence_count == 1
    assert f.risk_explanation  # populated from risk_factors
    assert data.severity_counts()[f.severity] == 1


async def test_generate_writes_files(ctx: AppContext, tmp_path: Path) -> None:
    scan_uuid = await _scan(ctx)
    with ctx.session() as s:
        data = ReportBuilder(s).for_scan(scan_uuid)
    written = generate_reports(data, ["json", "sarif", "html"], tmp_path)
    assert set(written) == {"json", "sarif", "html"}
    for path in written.values():
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0


async def test_gate_on_report(ctx: AppContext) -> None:
    scan_uuid = await _scan(ctx)
    with ctx.session() as s:
        data = ReportBuilder(s).for_scan(scan_uuid)
    # critical finding -> gate fails on high
    assert evaluate_gate(data, "high").passed is False
