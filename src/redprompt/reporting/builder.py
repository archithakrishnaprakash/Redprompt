"""Assemble :class:`ReportData` from the database (scan → target → findings)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from redprompt.db.models import Evidence, Finding, Scan, Target, TestCase
from redprompt.exceptions import ReportError
from redprompt.regression import RegressionService
from redprompt.reporting.data import FindingReport, ReportData
from redprompt.version import get_version


class ReportBuilder:
    def __init__(self, session: Session) -> None:
        self.session = session

    def for_scan(self, scan_uuid: str) -> ReportData:
        scan = self.session.scalar(select(Scan).where(Scan.scan_uuid == scan_uuid))
        if scan is None:
            raise ReportError(f"no such scan: {scan_uuid}")
        return self._assemble(scan)

    def latest_for_target(self, target_id: int) -> ReportData:
        scan = self.session.scalar(
            select(Scan)
            .where(Scan.target_id == target_id, Scan.dry_run.is_(False))
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        if scan is None:
            raise ReportError("no completed scans for this target")
        return self._assemble(scan)

    def _assemble(self, scan: Scan) -> ReportData:
        target: Target = scan.target
        findings = list(self.session.scalars(select(Finding).where(Finding.scan_id == scan.id)))

        finding_reports: list[FindingReport] = []
        for f in findings:
            evidence_count = (
                self.session.scalar(
                    select(func.count()).select_from(Evidence).where(Evidence.finding_id == f.id)
                )
                or 0
            )
            tc = self.session.scalar(select(TestCase).where(TestCase.test_id == f.test_id))
            finding_reports.append(
                FindingReport(
                    finding_id=f.finding_id,
                    test_id=f.test_id,
                    title=f.title,
                    category=f.category.value,
                    severity=f.severity.value,
                    confidence=f.confidence,
                    risk_score=f.risk_score,
                    status=f.status.value,
                    description=f.description,
                    impact=f.impact,
                    exploitability=f.exploitability.value,
                    remediation=f.remediation,
                    references=list(f.references or []),
                    reproduction_steps=list(f.reproduction_steps or []),
                    risk_explanation=(f.risk_factors or {}).get("explanation", ""),
                    risk_factors=f.risk_factors or {},
                    heuristic=tc.heuristic if tc else True,
                    experimental=tc.experimental if tc else False,
                    evidence_count=evidence_count,
                )
            )

        regression = None
        try:
            report = RegressionService(self.session).compare_latest(target.id)
            regression = {
                "verdict": report.verdict,
                "previous": report.previous,
                "new": report.new,
                "resolved": report.resolved,
                "unchanged": report.unchanged,
                "severity_delta": report.severity_delta,
            }
        except ValueError:
            regression = None

        return ReportData(
            tool_name="RedPrompt",
            tool_version=get_version(),
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            target={
                "name": target.name,
                "base_url": target.base_url,
                "app_type": target.app_type.value,
                "provider": target.llm_provider,
                "rag_enabled": target.rag_enabled,
                "agent_enabled": target.agent_enabled,
                "environment": target.environment,
            },
            scan={
                "scan_uuid": scan.scan_uuid,
                "status": scan.status.value,
                "categories": scan.categories,
                "total_tests": scan.total_tests,
                "passed": scan.passed,
                "failed": scan.failed,
                "inconclusive": scan.inconclusive,
                "errored": scan.errored,
                "skipped": scan.skipped,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            },
            findings=finding_reports,
            regression=regression,
        )
