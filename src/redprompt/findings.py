"""Finding and evidence query service (read-side)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from redprompt.db.models import Evidence, Finding, Retest
from redprompt.enums import FindingStatus, Severity
from redprompt.exceptions import RedPromptError


class FindingService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        target_id: int | None = None,
        category: str | None = None,
    ) -> list[Finding]:
        stmt = select(Finding)
        if severity:
            stmt = stmt.where(Finding.severity == Severity(severity))
        if status:
            stmt = stmt.where(Finding.status == FindingStatus(status))
        if target_id is not None:
            stmt = stmt.where(Finding.target_id == target_id)
        if category:
            stmt = stmt.where(Finding.category == category)
        findings = list(self.session.scalars(stmt))
        # Sort by severity rank desc, then confidence desc.
        findings.sort(key=lambda f: (f.severity.rank, f.confidence), reverse=True)
        return findings

    def get(self, finding_id: str) -> Finding:
        finding = self.session.scalar(select(Finding).where(Finding.finding_id == finding_id))
        if finding is None:
            raise RedPromptError(f"no such finding: {finding_id}")
        return finding

    def evidence_for(self, finding_id: str) -> list[Evidence]:
        finding = self.get(finding_id)
        stmt = select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.created_at)
        return list(self.session.scalars(stmt))

    def retests_for(self, finding_id: str) -> list[Retest]:
        finding = self.get(finding_id)
        stmt = (
            select(Retest)
            .where(Retest.finding_id == finding.id)
            .order_by(Retest.retest_number)
        )
        return list(self.session.scalars(stmt))

    def set_status(self, finding_id: str, status: FindingStatus) -> Finding:
        finding = self.get(finding_id)
        finding.status = status
        return finding
