"""Report data model — the pure, serialisable input to every report format.

A :class:`ReportData` is assembled once (from the database by the builder, or by
hand in tests) and then rendered to JSON / SARIF / HTML without touching the DB.
This keeps the formatters pure and independently testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redprompt.enums import Severity


@dataclass
class FindingReport:
    finding_id: str
    test_id: str
    title: str
    category: str
    severity: str
    confidence: float
    risk_score: float
    status: str
    description: str = ""
    impact: str = ""
    exploitability: str = "medium"
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    risk_explanation: str = ""
    risk_factors: dict[str, Any] = field(default_factory=dict)
    heuristic: bool = True
    experimental: bool = False
    evidence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "test_id": self.test_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "risk_score": self.risk_score,
            "status": self.status,
            "description": self.description,
            "impact": self.impact,
            "exploitability": self.exploitability,
            "remediation": self.remediation,
            "references": self.references,
            "reproduction_steps": self.reproduction_steps,
            "risk_explanation": self.risk_explanation,
            "risk_factors": self.risk_factors,
            "heuristic": self.heuristic,
            "experimental": self.experimental,
            "evidence_count": self.evidence_count,
        }


@dataclass
class ReportData:
    tool_name: str
    tool_version: str
    generated_at: str
    target: dict[str, Any]
    scan: dict[str, Any]
    findings: list[FindingReport] = field(default_factory=list)
    regression: dict[str, Any] | None = None

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def findings_sorted(self) -> list[FindingReport]:
        return sorted(
            self.findings,
            key=lambda f: (Severity(f.severity).rank, f.confidence),
            reverse=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "generated_at": self.generated_at,
            "target": self.target,
            "scan": self.scan,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings_sorted()],
            "regression": self.regression,
        }
