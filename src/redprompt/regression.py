"""Security regression comparison.

The pure core (:func:`compare_snapshots`) diffs two scan snapshots by test id and
severity — no database — so the comparison logic is deterministic and unit-tested
on its own. :class:`RegressionService` wraps it to load the two most recent scans
of a target from the database.

The verdict is derived from a documented severity-weighted score (the sum of
per-finding severity ranks), so "improved / regressed" is explainable rather than
an opaque single number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redprompt.enums import Severity

if TYPE_CHECKING:  # keep this module import-light (no SQLAlchemy at top level)
    from sqlalchemy.orm import Session

    from redprompt.db.models import Scan


@dataclass
class ScanSnapshot:
    scan_uuid: str
    findings: dict[str, str]  # test_id -> severity value

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for sev in self.findings.values():
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def weighted_score(self) -> int:
        return sum(Severity(sev).rank for sev in self.findings.values())


@dataclass
class RegressionReport:
    previous: str | None
    current: str
    new: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    previous_counts: dict[str, int] = field(default_factory=dict)
    current_counts: dict[str, int] = field(default_factory=dict)
    severity_delta: dict[str, int] = field(default_factory=dict)
    verdict: str = "baseline"


def compare_snapshots(previous: ScanSnapshot | None, current: ScanSnapshot) -> RegressionReport:
    current_counts = current.severity_counts()
    if previous is None:
        return RegressionReport(
            previous=None,
            current=current.scan_uuid,
            new=sorted(current.findings),
            current_counts=current_counts,
            severity_delta={s.value: current_counts[s.value] for s in Severity},
            verdict="baseline",
        )

    prev_ids = set(previous.findings)
    curr_ids = set(current.findings)
    new = sorted(curr_ids - prev_ids)
    resolved = sorted(prev_ids - curr_ids)
    unchanged = sorted(prev_ids & curr_ids)

    prev_counts = previous.severity_counts()
    severity_delta = {s.value: current_counts[s.value] - prev_counts[s.value] for s in Severity}

    prev_score = previous.weighted_score()
    curr_score = current.weighted_score()
    if curr_score < prev_score:
        verdict = "improved"
    elif curr_score > prev_score:
        verdict = "regressed"
    else:
        verdict = "unchanged"

    return RegressionReport(
        previous=previous.scan_uuid,
        current=current.scan_uuid,
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        previous_counts=prev_counts,
        current_counts=current_counts,
        severity_delta=severity_delta,
        verdict=verdict,
    )


class RegressionService:
    def __init__(self, session: "Session") -> None:
        self.session = session

    def _snapshot(self, scan: "Scan") -> ScanSnapshot:
        from sqlalchemy import select

        from redprompt.db.models import Finding

        findings = self.session.scalars(select(Finding).where(Finding.scan_id == scan.id))
        return ScanSnapshot(
            scan_uuid=scan.scan_uuid,
            findings={f.test_id: f.severity.value for f in findings},
        )

    def last_two_scans(self, target_id: int) -> tuple["Scan | None", "Scan"]:
        from sqlalchemy import select

        from redprompt.db.models import Scan

        scans = list(
            self.session.scalars(
                select(Scan)
                .where(Scan.target_id == target_id, Scan.dry_run.is_(False))
                .order_by(Scan.created_at.desc())
                .limit(2)
            )
        )
        if not scans:
            raise ValueError("no completed scans for this target")
        current = scans[0]
        previous = scans[1] if len(scans) > 1 else None
        return previous, current

    def compare_latest(self, target_id: int) -> RegressionReport:
        previous, current = self.last_two_scans(target_id)
        prev_snap = self._snapshot(previous) if previous else None
        return compare_snapshots(prev_snap, self._snapshot(current))
