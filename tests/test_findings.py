"""Tests for finding persistence, risk scoring, and the finding query service."""

from __future__ import annotations

import httpx

from redprompt.analysis.base import DetectionResult
from redprompt.core.context import AppContext
from redprompt.core.orchestrator import Orchestrator
from redprompt.enums import Category, Severity
from redprompt.evidence import verify_evidence
from redprompt.findings import FindingService
from redprompt.providers.base import ProviderRequest
from redprompt.targets.schemas import TargetCreate
from redprompt.targets.service import TargetService
from redprompt.tests_plugins.base import SecurityTest, TestContext, TestResult, make_probe_record
from redprompt.tests_plugins.registry import TestRegistry


class _CriticalTest(SecurityTest):
    id = "FN-CRIT-1"
    name = "critical leak"
    category = Category.DATA
    severity = Severity.CRITICAL

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("x"))
        det = DetectionResult.failed(0.95, "leaked", indicators=["s"], evidence=[resp.text])
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


class _LowConfTest(SecurityTest):
    id = "FN-LOWCONF-1"
    name = "weak signal"
    category = Category.PROMPT
    severity = Severity.HIGH

    async def execute(self, ctx: TestContext) -> TestResult:
        resp = await ctx.provider.generate(ProviderRequest.from_prompt("x"))
        det = DetectionResult.failed(0.4, "maybe", evidence=[resp.text])
        return self.result(det, probes=[make_probe_record("p", resp.request, resp, det)])


def _registry() -> TestRegistry:
    reg = TestRegistry()
    reg.register(_CriticalTest)
    reg.register(_LowConfTest)
    return reg


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "sk-RPLABSECRET000000000000"})


def _add_target(ctx: AppContext) -> None:
    with ctx.session() as s:
        TargetService(s).add(
            TargetCreate(name="lab", base_url="http://127.0.0.1:8000", provider="generic", authorized=True)
        )


async def test_risk_scored_and_explained(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    await orch.run_scan("lab", test_ids=["FN-CRIT-1"])
    with ctx.session() as s:
        f = FindingService(s).get(FindingService(s).list()[0].finding_id)
        assert f.risk_score > 0.0
        assert "explanation" in f.risk_factors
        assert "contributions" in f.risk_factors
        assert f.severity in (Severity.CRITICAL, Severity.HIGH)


async def test_low_confidence_gated_to_info(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    await orch.run_scan("lab", test_ids=["FN-LOWCONF-1"])
    with ctx.session() as s:
        findings = FindingService(s).list()
        assert len(findings) == 1
        # confidence 0.4 < default minimum_confidence 0.70 -> reported INFO
        assert findings[0].severity is Severity.INFO


async def test_finding_list_filters(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    await orch.run_scan("lab")
    with ctx.session() as s:
        svc = FindingService(s)
        assert len(svc.list()) == 2
        infos = svc.list(severity="info")
        assert all(f.severity.value == "info" for f in infos)


async def test_evidence_linked_and_verifiable(ctx: AppContext) -> None:
    _add_target(ctx)
    orch = Orchestrator(ctx, _registry(), transport=httpx.MockTransport(_handler))
    await orch.run_scan("lab", test_ids=["FN-CRIT-1"])
    with ctx.session() as s:
        svc = FindingService(s)
        fid = svc.list()[0].finding_id
        evidence = svc.evidence_for(fid)
        assert len(evidence) == 1
        e = evidence[0]
        assert verify_evidence(
            {
                "request": e.request, "response": e.response, "headers": e.headers,
                "detection_result": e.detection_result, "snippets": e.snippets,
                "content_hash": e.content_hash,
            }
        )
        # secret must have been redacted before persistence
        assert "sk-RPLABSECRET000000000000" not in str(e.response)
