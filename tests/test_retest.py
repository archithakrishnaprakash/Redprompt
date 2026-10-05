"""Tests for the retest engine and regression service (DB + MockTransport)."""

from __future__ import annotations

import httpx

from redprompt.analysis.base import DetectionResult
from redprompt.analysis.detectors import detect_markers
from redprompt.core.context import AppContext
from redprompt.core.orchestrator import Orchestrator
from redprompt.enums import Category, FindingStatus, RetestStatus, Severity
from redprompt.findings import FindingService
from redprompt.regression import RegressionService
from redprompt.retest import RetestEngine
from redprompt.targets.schemas import TargetCreate
from redprompt.targets.service import TargetService
from redprompt.tests_plugins.base import SingleProbeTest, TestContext
from redprompt.tests_plugins.registry import TestRegistry


class _MarkerTest(SingleProbeTest):
    id = "RT-MARK-1"
    name = "marker test"
    category = Category.PROMPT
    severity = Severity.HIGH
    probe_prompt = "probe"

    def analyze(self, response_text: str, ctx: TestContext):
        return detect_markers(response_text, ["VULN"], confidence=0.9, reason="marker present")


def _registry() -> TestRegistry:
    reg = TestRegistry()
    reg.register(_MarkerTest)
    return reg


def _vuln(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "VULN present"})


def _safe(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "I cannot do that"})


def _add_target(ctx: AppContext) -> None:
    with ctx.session() as s:
        TargetService(s).add(
            TargetCreate(name="lab", base_url="http://127.0.0.1:8000", provider="generic", authorized=True)
        )


async def test_retest_remediated(ctx: AppContext) -> None:
    _add_target(ctx)
    reg = _registry()
    await Orchestrator(ctx, reg, transport=httpx.MockTransport(_vuln)).run_scan("lab")
    with ctx.session() as s:
        fid = FindingService(s).list()[0].finding_id

    outcome = await RetestEngine(ctx, reg, transport=httpx.MockTransport(_safe)).retest(fid)
    assert outcome.new_status == FindingStatus.REMEDIATED.value
    assert outcome.result_status == "pass"
    with ctx.session() as s:
        f = FindingService(s).get(fid)
        assert f.status is FindingStatus.REMEDIATED
        assert f.retest_status is RetestStatus.COMPLETED
        assert len(FindingService(s).retests_for(fid)) == 1


async def test_retest_still_vulnerable(ctx: AppContext) -> None:
    _add_target(ctx)
    reg = _registry()
    await Orchestrator(ctx, reg, transport=httpx.MockTransport(_vuln)).run_scan("lab")
    with ctx.session() as s:
        fid = FindingService(s).list()[0].finding_id

    outcome = await RetestEngine(ctx, reg, transport=httpx.MockTransport(_vuln)).retest(fid)
    assert outcome.new_status == FindingStatus.STILL_VULNERABLE.value
    with ctx.session() as s:
        assert FindingService(s).get(fid).status is FindingStatus.STILL_VULNERABLE


async def test_regression_improved(ctx: AppContext) -> None:
    _add_target(ctx)
    reg = _registry()
    # First scan: vulnerable (1 finding). Second scan: fixed (0 findings).
    await Orchestrator(ctx, reg, transport=httpx.MockTransport(_vuln)).run_scan("lab")
    await Orchestrator(ctx, reg, transport=httpx.MockTransport(_safe)).run_scan("lab")
    with ctx.session() as s:
        target_id = TargetService(s).get("lab").id
        report = RegressionService(s).compare_latest(target_id)
    assert report.verdict == "improved"
    assert "RT-MARK-1" in report.resolved


async def test_regression_baseline_single_scan(ctx: AppContext) -> None:
    _add_target(ctx)
    reg = _registry()
    await Orchestrator(ctx, reg, transport=httpx.MockTransport(_vuln)).run_scan("lab")
    with ctx.session() as s:
        target_id = TargetService(s).get("lab").id
        report = RegressionService(s).compare_latest(target_id)
    assert report.verdict == "baseline"
