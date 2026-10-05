"""Offline tests for the transparent risk engine."""

from __future__ import annotations

import unittest

from redprompt.config import RiskConfig
from redprompt.enums import Exploitability, Severity
from redprompt.risk import RiskEngine, RiskInput, severity_from_score


class TestBanding(unittest.TestCase):
    def test_bands(self) -> None:
        self.assertIs(severity_from_score(9.5), Severity.CRITICAL)
        self.assertIs(severity_from_score(7.0), Severity.HIGH)
        self.assertIs(severity_from_score(4.0), Severity.MEDIUM)
        self.assertIs(severity_from_score(2.0), Severity.LOW)
        self.assertIs(severity_from_score(1.0), Severity.INFO)


class TestRiskEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskEngine(RiskConfig(minimum_confidence=0.70))

    def test_deterministic(self) -> None:
        ri = RiskInput(Severity.HIGH, Exploitability.HIGH, confidence=0.9, exposure=0.8)
        a = self.engine.assess(ri)
        b = self.engine.assess(ri)
        self.assertEqual(a.score, b.score)
        self.assertEqual(a.severity, b.severity)

    def test_critical_case_scores_high(self) -> None:
        ri = RiskInput(Severity.CRITICAL, Exploitability.HIGH, confidence=0.95, exposure=1.0)
        result = self.engine.assess(ri)
        self.assertGreaterEqual(result.score, 9.0)
        self.assertIs(result.severity, Severity.CRITICAL)

    def test_factors_breakdown_present(self) -> None:
        result = self.engine.assess(RiskInput(Severity.HIGH, Exploitability.MEDIUM, confidence=0.9))
        self.assertIn("contributions", result.factors)
        self.assertIn("weights", result.factors)
        self.assertIn("score", result.factors)
        # contributions sum (pre-modifier) approximately equals score/10
        self.assertTrue(result.explanation)

    def test_low_confidence_gated_to_info(self) -> None:
        result = self.engine.assess(
            RiskInput(Severity.CRITICAL, Exploitability.HIGH, confidence=0.4, exposure=1.0)
        )
        self.assertIs(result.severity, Severity.INFO)
        self.assertTrue(result.factors["confidence_gate"]["below_threshold"])

    def test_persistent_raises_score(self) -> None:
        base = RiskInput(Severity.MEDIUM, Exploitability.MEDIUM, confidence=0.9, exposure=0.7)
        persistent = RiskInput(
            Severity.MEDIUM, Exploitability.MEDIUM, confidence=0.9, exposure=0.7, persistent=True
        )
        self.assertGreater(self.engine.assess(persistent).score, self.engine.assess(base).score)

    def test_requires_privilege_lowers_score(self) -> None:
        base = RiskInput(Severity.HIGH, Exploitability.HIGH, confidence=0.9, exposure=0.8)
        gated = RiskInput(
            Severity.HIGH, Exploitability.HIGH, confidence=0.9, exposure=0.8, requires_privilege=True
        )
        self.assertLess(self.engine.assess(gated).score, self.engine.assess(base).score)

    def test_disabling_confidence_weight_renormalises(self) -> None:
        engine = RiskEngine(RiskConfig(confidence_weight=False, minimum_confidence=0.0))
        result = engine.assess(RiskInput(Severity.HIGH, Exploitability.MEDIUM, confidence=0.1))
        self.assertNotIn("confidence", result.factors["weights"])
        # weights renormalise to sum ~1.0 (values are rounded to 3dp for display)
        self.assertAlmostEqual(sum(result.factors["weights"].values()), 1.0, places=2)

    def test_score_bounds(self) -> None:
        low = self.engine.assess(RiskInput(Severity.INFO, Exploitability.LOW, confidence=0.0, exposure=0.0))
        self.assertGreaterEqual(low.score, 0.0)
        high = self.engine.assess(RiskInput(Severity.CRITICAL, Exploitability.HIGH, confidence=1.0, exposure=1.0, persistent=True))
        self.assertLessEqual(high.score, 10.0)


if __name__ == "__main__":
    unittest.main()
