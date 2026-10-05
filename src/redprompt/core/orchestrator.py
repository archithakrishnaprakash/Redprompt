"""Scan orchestrator — the DB-backed pipeline around the pure scan engine.

    load target → validate scope → build plan → snapshot test cases → create scan
    → run engine → persist executions + (redacted, hashed) evidence + findings
    → update scan counters → return a summary

Risk scoring and remediation are refined by the Risk engine in Phase 5; here each
FAIL becomes an OPEN finding carrying the test's default severity so the pipeline
is end-to-end from Phase 3 onward.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, select

from redprompt.core.context import AppContext
from redprompt.core.engine import ScanEngine
from redprompt.db.base import utcnow
from redprompt.db.models import Evidence, Finding, Scan, TestCase, TestExecution
from redprompt.enums import (
    Category,
    Exploitability,
    FindingStatus,
    RetestStatus,
    ScanStatus,
    Severity,
    TestStatus,
)
from redprompt.evidence import build_evidence_payload
from redprompt.exceptions import SafetyViolation
from redprompt.risk import RiskEngine, RiskInput
from redprompt.safety import SafetyDecision
from redprompt.targets.schemas import connection_from_target
from redprompt.targets.service import TargetService, make_client
from redprompt.providers import build_provider
from redprompt.tests_plugins.base import SecurityTest, TargetInfo, TestResult
from redprompt.tests_plugins.registry import TestRegistry, build_registry

_CATEGORY_ABBR = {
    Category.PROMPT: "PROMPT",
    Category.DATA: "DATA",
    Category.RAG: "RAG",
    Category.AGENT: "AGENT",
    Category.API: "API",
    Category.FILE: "FILE",
}


@dataclass
class FindingSummary:
    finding_id: str
    title: str
    severity: str
    confidence: float
    test_id: str


@dataclass
class ScanSummary:
    scan_uuid: str
    target_name: str
    dry_run: bool
    status: str
    counts: dict[str, int]
    safety: SafetyDecision
    findings: list[FindingSummary] = field(default_factory=list)
    plan_size: int = 0


class Orchestrator:
    def __init__(
        self,
        ctx: AppContext,
        registry: TestRegistry | None = None,
        *,
        transport: object | None = None,
        inspector: object | None = None,
    ) -> None:
        self.ctx = ctx
        self.registry = registry or build_registry()
        self.transport = transport
        self.inspector = inspector
        self.risk_engine = RiskEngine(ctx.settings.risk)

    def plan_for(
        self,
        target_info: TargetInfo,
        *,
        categories: list[str] | None = None,
        test_ids: list[str] | None = None,
    ) -> list[SecurityTest]:
        return self.registry.for_target(target_info, categories=categories, test_ids=test_ids)

    async def run_scan(
        self,
        identifier: str | int,
        *,
        categories: list[str] | None = None,
        test_ids: list[str] | None = None,
        dry_run: bool = False,
        workers: int | None = None,
        env: dict[str, str] | None = None,
    ) -> ScanSummary:
        # --- 1. load target, build plan, create scan row --------------------
        with self.ctx.session() as session:
            target = TargetService(session).get(identifier)
            info = _target_info(target)
            conn = connection_from_target(target)
            provider_name = target.llm_provider or "generic"
            plan = self.plan_for(info, categories=categories, test_ids=test_ids)
            _snapshot_test_cases(session, plan)

            scan = Scan(
                scan_uuid=str(uuid.uuid4()),
                target_id=target.id,
                status=ScanStatus.RUNNING,
                categories=categories or sorted({t.category.value for t in plan}),
                dry_run=dry_run,
                started_at=utcnow(),
                config_snapshot={
                    "workers": workers or self.ctx.settings.scan.workers,
                    "minimum_confidence": self.ctx.settings.risk.minimum_confidence,
                },
            )
            session.add(scan)
            session.flush()
            scan_id = scan.id
            scan_uuid = scan.scan_uuid
            target_id = target.id
            target_name = target.name
            environment = target.environment
            auth_method = (
                target.auth_method.value
                if hasattr(target.auth_method, "value")
                else str(target.auth_method)
            )
            # Exposure heuristic: an unauthenticated surface is more reachable.
            exposure = 0.5 if auth_method not in ("none", "", None) else 0.8

        # --- 2. build client + provider, run the engine ---------------------
        client = make_client(self.ctx.settings, transport=self.transport, inspector=self.inspector)
        provider = build_provider(provider_name, conn, client, env=env)
        engine = ScanEngine(self.ctx.settings)
        aborted = False
        try:
            engine_result = await engine.run(
                info, provider, plan, dry_run=dry_run, workers=workers, logger=self.ctx.log
            )
        except SafetyViolation:
            aborted = True
            with self.ctx.session() as session:
                scan = session.get(Scan, scan_id)
                if scan is not None:
                    scan.status = ScanStatus.ABORTED
                    scan.finished_at = utcnow()
            raise
        finally:
            await client.aclose()

        # --- 3. persist results, evidence, findings -------------------------
        finding_summaries: list[FindingSummary] = []
        with self.ctx.session() as session:
            for result in engine_result.results:
                execution = _persist_execution(session, scan_id, result)
                session.flush()
                finding = None
                if result.is_finding:
                    finding = _create_finding(
                        session, scan_id, target_id, execution.id, result,
                        self.registry, self.risk_engine, exposure,
                    )
                    session.flush()
                    finding_summaries.append(
                        FindingSummary(
                            finding_id=finding.finding_id,
                            title=finding.title,
                            severity=finding.severity.value,
                            confidence=finding.confidence,
                            test_id=finding.test_id,
                        )
                    )
                _persist_evidence(
                    session, result, execution.id,
                    finding.id if finding else None, environment,
                    self.ctx.settings.security.redact_secrets,
                )

            scan = session.get(Scan, scan_id)
            assert scan is not None
            counts = engine_result.counts
            scan.total_tests = counts["total"]
            scan.passed = counts[TestStatus.PASS.value]
            scan.failed = counts[TestStatus.FAIL.value]
            scan.inconclusive = counts[TestStatus.INCONCLUSIVE.value]
            scan.errored = counts[TestStatus.ERROR.value]
            scan.skipped = counts[TestStatus.SKIPPED.value]
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = utcnow()

        return ScanSummary(
            scan_uuid=scan_uuid,
            target_name=target_name,
            dry_run=dry_run,
            status=ScanStatus.ABORTED.value if aborted else ScanStatus.COMPLETED.value,
            counts=engine_result.counts,
            safety=engine_result.safety,
            findings=finding_summaries,
            plan_size=len(plan),
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _target_info(target: object) -> TargetInfo:
    tools = [t.name for t in getattr(target, "tools", [])]
    app_type = target.app_type.value if hasattr(target.app_type, "value") else str(target.app_type)
    auth_method = (
        target.auth_method.value if hasattr(target.auth_method, "value") else str(target.auth_method)
    )
    return TargetInfo(
        name=target.name,
        base_url=target.base_url,
        app_type=app_type,
        auth_method=auth_method,
        authorized=target.authorized,
        rag_enabled=target.rag_enabled,
        agent_enabled=target.agent_enabled,
        file_upload=target.file_upload,
        streaming=target.streaming,
        tools=tools,
        environment=target.environment,
        tags=list(target.tags or []),
    )


def _snapshot_test_cases(session: object, plan: list[SecurityTest]) -> None:
    for test in plan:
        existing = session.scalar(select(TestCase).where(TestCase.test_id == test.id))  # type: ignore[attr-defined]
        if existing:
            continue
        meta = test.as_metadata()
        session.add(  # type: ignore[attr-defined]
            TestCase(
                test_id=meta["test_id"],
                name=meta["name"],
                category=Category(meta["category"]),
                description=meta["description"],
                default_severity=Severity(meta["default_severity"]),
                version=meta["version"],
                experimental=meta["experimental"],
                heuristic=meta["heuristic"],
                references=meta["references"],
            )
        )


def _persist_execution(session: object, scan_id: int, result: TestResult) -> TestExecution:
    execution = TestExecution(
        scan_id=scan_id,
        test_id=result.test_id,
        status=result.status,
        confidence=result.confidence,
        duration_ms=result.duration_ms,
        reason=result.reason,
        indicators=result.indicators,
        started_at=utcnow(),
        finished_at=utcnow(),
    )
    session.add(execution)  # type: ignore[attr-defined]
    return execution


def _next_finding_id(session: object, category: Category) -> str:
    count = session.scalar(select(func.count()).select_from(Finding)) or 0  # type: ignore[attr-defined]
    abbr = _CATEGORY_ABBR.get(category, "GEN")
    return f"RP-{abbr}-{count + 1:04d}"


def _create_finding(
    session: object,
    scan_id: int,
    target_id: int,
    execution_id: int,
    result: TestResult,
    registry: TestRegistry,
    risk_engine: RiskEngine,
    exposure: float,
) -> Finding:
    # Metadata comes from the registered test for title/description/remediation.
    test = _safe_get(registry, result.test_id)
    title = test.name if test else result.test_id
    category = test.category if test else Category.PROMPT
    description = test.description if test else ""
    remediation = test.remediation() if test else ""
    references = list(test.references) if test else []
    exploitability = test.exploitability if test else Exploitability.MEDIUM
    impact = test.impact_text() if test else ""
    persistent = test.persistent if test else False
    requires_privilege = test.requires_privilege if test else False

    risk = risk_engine.assess(
        RiskInput(
            base_severity=result.severity,
            exploitability=exploitability,
            confidence=result.confidence,
            exposure=exposure,
            persistent=persistent,
            requires_privilege=requires_privilege,
        )
    )
    risk_factors = dict(risk.factors)
    risk_factors["explanation"] = risk.explanation

    finding = Finding(
        finding_id=_next_finding_id(session, category),
        scan_id=scan_id,
        execution_id=execution_id,
        target_id=target_id,
        test_id=result.test_id,
        title=title,
        category=category,
        description=description,
        affected_component=category.value,
        impact=impact,
        exploitability=exploitability,
        confidence=result.confidence,
        severity=risk.severity,  # explainable, risk-banded severity
        risk_score=risk.score,
        risk_factors=risk_factors,
        remediation=remediation,
        references=references,
        reproduction_steps=_reproduction_steps(result),
        status=FindingStatus.OPEN,
        retest_status=RetestStatus.PENDING,
    )
    session.add(finding)  # type: ignore[attr-defined]
    return finding


def _safe_get(registry: TestRegistry, test_id: str) -> SecurityTest | None:
    try:
        return registry.get(test_id)
    except Exception:  # noqa: BLE001 - metadata lookup is best-effort
        return None


def _reproduction_steps(result: TestResult) -> list[str]:
    steps: list[str] = []
    for probe in result.probes:
        status = probe.response.get("status_code")
        steps.append(f"Sent probe '{probe.label}' → HTTP {status}; detection: {result.reason}")
    return steps or [result.reason]


def _persist_evidence(
    session: object,
    result: TestResult,
    execution_id: int,
    finding_id: int | None,
    environment: str,
    redact_secrets: bool,
) -> None:
    for probe in result.probes:
        payload = build_evidence_payload(
            probe,
            test_id=result.test_id,
            environment=environment,
            redact_secrets=redact_secrets,
        )
        session.add(  # type: ignore[attr-defined]
            Evidence(
                execution_id=execution_id,
                finding_id=finding_id,
                test_id=payload["test_id"],
                request=payload["request"],
                response=payload["response"],
                headers=payload["headers"],
                prompt_context=payload["prompt_context"],
                tool_invocation=payload["tool_invocation"],
                detection_result=payload["detection_result"],
                snippets=payload["snippets"],
                content_hash=payload["content_hash"],
                environment=payload["environment"],
                target_version=payload["target_version"],
            )
        )
