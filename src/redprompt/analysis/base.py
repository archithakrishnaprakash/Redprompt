"""Detection-result contract and signal combination — pure, no heavy deps.

Detection is explicitly *layered*: individual detectors each emit a
:class:`DetectionResult`, and :func:`combine` fuses them without ever inventing a
vulnerability. The contract mirrors the spec:

    {"status": "...", "confidence": 0.0, "indicators": [], "evidence": [], "reason": ""}

Honesty rules baked in:
- an unusual response is *not* automatically a failure — a detector must produce
  a concrete indicator to raise confidence;
- confidence is bounded to [0, 1];
- ``combine`` takes the strongest signal, so one weak heuristic cannot on its own
  push a finding over the reporting threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redprompt.enums import TestStatus


@dataclass
class DetectionResult:
    status: TestStatus
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    reason: str = ""

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, self.confidence))

    @classmethod
    def passed(cls, reason: str = "expected secure behavior observed") -> DetectionResult:
        return cls(TestStatus.PASS, 0.0, reason=reason)

    @classmethod
    def failed(
        cls, confidence: float, reason: str, *, indicators: list[str] | None = None,
        evidence: list[str] | None = None,
    ) -> DetectionResult:
        return cls(TestStatus.FAIL, confidence, indicators or [], evidence or [], reason)

    @classmethod
    def inconclusive(cls, reason: str, confidence: float = 0.0) -> DetectionResult:
        return cls(TestStatus.INCONCLUSIVE, confidence, reason=reason)

    @classmethod
    def error(cls, reason: str) -> DetectionResult:
        return cls(TestStatus.ERROR, 0.0, reason=reason)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": round(self.confidence, 3),
            "indicators": self.indicators,
            "evidence": self.evidence,
            "reason": self.reason,
        }


def combine(results: list[DetectionResult]) -> DetectionResult:
    """Fuse layered detector outputs.

    - ERROR dominates (a broken measurement is not a pass).
    - Otherwise, if any detector FAILs, the combined result FAILs with the highest
      confidence seen and the union of indicators/evidence.
    - Else if all are PASS, the result PASSes.
    - Else it is INCONCLUSIVE.
    """
    if not results:
        return DetectionResult.inconclusive("no detectors ran")

    if any(r.status is TestStatus.ERROR for r in results):
        errs = [r.reason for r in results if r.status is TestStatus.ERROR]
        return DetectionResult.error("; ".join(errs) or "detector error")

    fails = [r for r in results if r.status is TestStatus.FAIL]
    if fails:
        best = max(fails, key=lambda r: r.confidence)
        indicators: list[str] = []
        evidence: list[str] = []
        for r in fails:
            indicators.extend(r.indicators)
            evidence.extend(r.evidence)
        return DetectionResult(
            status=TestStatus.FAIL,
            confidence=best.confidence,
            indicators=_dedupe(indicators),
            evidence=_dedupe(evidence),
            reason=best.reason,
        )

    if all(r.status is TestStatus.PASS for r in results):
        return DetectionResult.passed()

    return DetectionResult.inconclusive("mixed/insufficient signals")


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)
