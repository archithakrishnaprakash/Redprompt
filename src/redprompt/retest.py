"""Retest engine.

Re-runs the single test behind a finding and compares the new behaviour to the
original, updating the finding's lifecycle status and recording a :class:`Retest`
row with before/after evidence. Reuses the pure :class:`ScanEngine` so scope/safety
enforcement is identical to a full scan.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select

from redprompt.core.context import AppContext
from redprompt.core.engine import ScanEngine
from redprompt.core.orchestrator import _target_info
from redprompt.db.base import utcnow
from redprompt.db.models import Evidence, Finding, Retest
from redprompt.enums import FindingStatus, RetestStatus, TestStatus
from redprompt.evidence import build_evidence_payload
from redprompt.findings import FindingService
from redprompt.providers import build_provider
from redprompt.targets.schemas import connection_from_target
from redprompt.targets.service import TargetService, make_client
from redprompt.tests_plugins.registry import TestRegistry, build_registry

_RESULT_TO_FINDING = {
    TestStatus.PASS: FindingStatus.REMEDIATED,
    TestStatus.INCONCLUSIVE: FindingStatus.RETEST_REQUIRED,
    TestStatus.FAIL: FindingStatus.STILL_VULNERABLE,
    TestStatus.ERROR: FindingStatus.RETEST_REQUIRED,
    TestStatus.SKIPPED: FindingStatus.RETEST_REQUIRED,
}


@dataclass
class RetestOutcome:
    finding_id: str
    previous_status: str
    new_status: str
    result_status: str
    retest_number: int
    confidence: float
    explanation: str


class RetestEngine:
    def __init__(
        self,
        ctx: AppContext,
        registry: TestRegistry | None = None,
        *,
        transport: object | None = None,
    ) -> None:
        self.ctx = ctx
        self.registry = registry or build_registry()
        self.transport = transport

    async def retest(self, finding_id: str) -> RetestOutcome:
        # --- 1. load finding + target ---------------------------------------
        with self.ctx.session() as session:
            finding = FindingService(session).get(finding_id)
            previous_status = finding.status.value
            test_id = finding.test_id
            finding_pk = finding.id
            environment_target_id = finding.target_id
            target = TargetService(session).get(environment_target_id)
            info = _target_info(target)
            conn = connection_from_target(target)
            provider_name = target.llm_provider or "generic"
            environment = target.environment
            prev_evidence_id = session.scalar(
                select(Evidence.id)
                .where(Evidence.finding_id == finding_pk)
                .order_by(Evidence.created_at.desc())
                .limit(1)
            )
            retest_number = (
                session.scalar(select(func.count()).select_from(Retest).where(Retest.finding_id == finding_pk))
                or 0
            ) + 1

        # --- 2. resolve the test plugin -------------------------------------
        try:
            test = self.registry.get(test_id)
        except Exception:  # noqa: BLE001 - unknown/removed plugin
            with self.ctx.session() as session:
                f = FindingService(session).get(finding_id)
                f.retest_status = RetestStatus.RETEST_REQUIRED
            return RetestOutcome(
                finding_id=finding_id,
                previous_status=previous_status,
                new_status=FindingStatus.RETEST_REQUIRED.value,
                result_status=TestStatus.ERROR.value,
                retest_number=retest_number,
                confidence=0.0,
                explanation=f"test plugin {test_id!r} is not available; cannot retest automatically",
            )

        # --- 3. run just this test ------------------------------------------
        client = make_client(self.ctx.settings, transport=self.transport)
        provider = build_provider(provider_name, conn, client)
        engine = ScanEngine(self.ctx.settings)
        try:
            engine_result = await engine.run(info, provider, [test], logger=self.ctx.log)
        finally:
            await client.aclose()
        result = engine_result.results[0]
        new_finding_status = _RESULT_TO_FINDING[result.status]

        # --- 4. persist retest + evidence + status --------------------------
        with self.ctx.session() as session:
            new_evidence_id = None
            for probe in result.probes:
                payload = build_evidence_payload(
                    probe, test_id=test_id, environment=environment,
                    redact_secrets=self.ctx.settings.security.redact_secrets,
                )
                ev = Evidence(
                    finding_id=finding_pk,
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
                session.add(ev)
                session.flush()
                new_evidence_id = ev.id

            session.add(
                Retest(
                    finding_id=finding_pk,
                    retest_number=retest_number,
                    status=result.status,
                    previous_evidence_id=prev_evidence_id,
                    new_evidence_id=new_evidence_id,
                    notes=result.reason,
                )
            )
            f = FindingService(session).get(finding_id)
            f.status = new_finding_status
            f.retest_status = RetestStatus.COMPLETED

        explanation = (
            f"Retest #{retest_number}: test returned {result.status.value} "
            f"(was {previous_status}) → finding is now {new_finding_status.value}."
        )
        return RetestOutcome(
            finding_id=finding_id,
            previous_status=previous_status,
            new_status=new_finding_status.value,
            result_status=result.status.value,
            retest_number=retest_number,
            confidence=result.confidence,
            explanation=explanation,
        )
