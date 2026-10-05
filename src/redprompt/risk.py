"""Transparent, explainable risk engine — pure, deterministic, no black box.

A finding's risk is a weighted blend of documented factors, each in [0, 1]:

    impact          how bad the outcome is (derived from the test's base severity)
    exploitability  how easy it is to trigger
    exposure        how reachable/authenticated the affected surface is
    confidence      how sure the detector is that this is real

The final 0–10 score is the weighted mean of the *enabled* factors (weights
renormalised when a factor is disabled in config), with two documented modifiers:
a persistent issue is scaled up slightly, and one that requires privilege has its
exploitability reduced. Every finding carries a ``risk_factors`` breakdown so a
reader can see exactly why it scored as it did — there is no hidden number.

If a finding's confidence is below ``risk.minimum_confidence`` it is reported as
INFO regardless of score (we don't over-claim on weak signals).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redprompt.config import RiskConfig
from redprompt.enums import Exploitability, Severity

# Base weights (before renormalisation for disabled factors).
_WEIGHTS = {"impact": 0.40, "exploitability": 0.25, "exposure": 0.15, "confidence": 0.20}

_IMPACT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}
_EXPLOIT = {Exploitability.HIGH: 0.9, Exploitability.MEDIUM: 0.6, Exploitability.LOW: 0.3}

_PERSISTENCE_MULTIPLIER = 1.10
_PRIVILEGE_EXPLOIT_PENALTY = 0.3


@dataclass
class RiskInput:
    base_severity: Severity
    exploitability: Exploitability = Exploitability.MEDIUM
    confidence: float = 0.0
    exposure: float = 0.7  # 1.0 = unauthenticated/broadly reachable; lower = gated
    persistent: bool = False
    requires_privilege: bool = False


@dataclass
class RiskResult:
    score: float  # 0..10
    severity: Severity
    factors: dict = field(default_factory=dict)
    explanation: str = ""


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 2.0:
        return Severity.LOW
    return Severity.INFO


class RiskEngine:
    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def _enabled_weights(self) -> dict[str, float]:
        weights = dict(_WEIGHTS)
        if not self.config.impact_weight:
            weights.pop("impact", None)
        if not self.config.exploitability_weight:
            weights.pop("exploitability", None)
        if not self.config.confidence_weight:
            weights.pop("confidence", None)
        # exposure is always considered.
        total = sum(weights.values()) or 1.0
        return {k: v / total for k, v in weights.items()}

    def assess(self, ri: RiskInput) -> RiskResult:
        exploit = _EXPLOIT[ri.exploitability]
        if ri.requires_privilege:
            exploit = max(0.0, exploit - _PRIVILEGE_EXPLOIT_PENALTY)

        raw = {
            "impact": _IMPACT[ri.base_severity],
            "exploitability": exploit,
            "exposure": max(0.0, min(1.0, ri.exposure)),
            "confidence": max(0.0, min(1.0, ri.confidence)),
        }
        weights = self._enabled_weights()

        contributions = {k: round(raw[k] * w, 4) for k, w in weights.items()}
        score01 = sum(contributions.values())
        if ri.persistent:
            score01 = min(1.0, score01 * _PERSISTENCE_MULTIPLIER)
        score = round(score01 * 10, 1)

        severity = severity_from_score(score)
        below_confidence = ri.confidence < self.config.minimum_confidence
        if below_confidence:
            severity = Severity.INFO

        factors = {
            "inputs": {
                "base_severity": ri.base_severity.value,
                "exploitability": ri.exploitability.value,
                "exposure": raw["exposure"],
                "confidence": round(ri.confidence, 3),
                "persistent": ri.persistent,
                "requires_privilege": ri.requires_privilege,
            },
            "weights": {k: round(w, 3) for k, w in weights.items()},
            "normalized_values": {k: round(v, 3) for k, v in raw.items() if k in weights},
            "contributions": contributions,
            "persistence_multiplier": _PERSISTENCE_MULTIPLIER if ri.persistent else 1.0,
            "score": score,
            "confidence_gate": {
                "minimum_confidence": self.config.minimum_confidence,
                "below_threshold": below_confidence,
            },
        }
        explanation = self._explain(ri, score, severity, below_confidence)
        return RiskResult(score=score, severity=severity, factors=factors, explanation=explanation)

    def _explain(
        self, ri: RiskInput, score: float, severity: Severity, gated: bool
    ) -> str:
        parts = [
            f"base impact from {ri.base_severity.value} severity",
            f"{ri.exploitability.value} exploitability",
            f"exposure {ri.exposure:.2f}",
            f"detector confidence {ri.confidence:.0%}",
        ]
        if ri.persistent:
            parts.append("persistent (x1.1)")
        if ri.requires_privilege:
            parts.append("requires privilege (exploitability reduced)")
        text = f"Risk {score}/10 → {severity.value.upper()} from " + ", ".join(parts) + "."
        if gated:
            text += (
                f" Reported as INFO because confidence {ri.confidence:.0%} is below the "
                f"{self.config.minimum_confidence:.0%} reporting threshold."
            )
        return text
