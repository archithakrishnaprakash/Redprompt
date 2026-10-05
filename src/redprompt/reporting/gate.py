"""CI security gate: fail a build when findings meet/exceed a severity threshold.

Pure and deterministic so it can be unit-tested and reused by the CLI ``gate``
command. Findings reported as INFO (e.g. gated by low confidence) never trip the
gate unless the threshold is explicitly ``info``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redprompt.enums import Severity
from redprompt.reporting.data import ReportData


@dataclass
class GateResult:
    passed: bool
    threshold: str
    offending: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1

    def message(self) -> str:
        if self.passed:
            return f"Security gate PASSED (threshold: {self.threshold})."
        return (
            f"Security gate FAILED (threshold: {self.threshold}): "
            f"{len(self.offending)} finding(s) at or above threshold: "
            + ", ".join(self.offending)
        )


def evaluate_gate(report: ReportData, fail_on: str) -> GateResult:
    threshold = Severity(fail_on)
    offending = [
        f.finding_id
        for f in report.findings_sorted()
        if Severity(f.severity).rank >= threshold.rank
    ]
    return GateResult(
        passed=not offending,
        threshold=threshold.value,
        offending=offending,
        counts=report.severity_counts(),
    )
