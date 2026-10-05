"""Offline tests for the detection-result contract and signal combination."""

from __future__ import annotations

import unittest

from redprompt.analysis.base import DetectionResult, combine
from redprompt.enums import TestStatus


class TestDetectionResult(unittest.TestCase):
    def test_confidence_clamped(self) -> None:
        self.assertEqual(DetectionResult(TestStatus.FAIL, 5.0).confidence, 1.0)
        self.assertEqual(DetectionResult(TestStatus.FAIL, -1.0).confidence, 0.0)

    def test_builders(self) -> None:
        self.assertIs(DetectionResult.passed().status, TestStatus.PASS)
        self.assertIs(DetectionResult.failed(0.5, "x").status, TestStatus.FAIL)
        self.assertIs(DetectionResult.inconclusive("y").status, TestStatus.INCONCLUSIVE)
        self.assertIs(DetectionResult.error("z").status, TestStatus.ERROR)

    def test_as_dict_shape(self) -> None:
        d = DetectionResult.failed(0.912, "leak", indicators=["i"], evidence=["e"]).as_dict()
        self.assertEqual(set(d), {"status", "confidence", "indicators", "evidence", "reason"})
        self.assertEqual(d["confidence"], 0.912)
        self.assertEqual(d["status"], "fail")


class TestCombine(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertIs(combine([]).status, TestStatus.INCONCLUSIVE)

    def test_error_dominates(self) -> None:
        results = [DetectionResult.passed(), DetectionResult.error("broke")]
        self.assertIs(combine(results).status, TestStatus.ERROR)

    def test_fail_wins_with_max_confidence(self) -> None:
        results = [
            DetectionResult.failed(0.6, "a", indicators=["x"]),
            DetectionResult.failed(0.9, "b", indicators=["y"]),
            DetectionResult.passed(),
        ]
        out = combine(results)
        self.assertIs(out.status, TestStatus.FAIL)
        self.assertEqual(out.confidence, 0.9)
        self.assertEqual(set(out.indicators), {"x", "y"})

    def test_all_pass(self) -> None:
        self.assertIs(combine([DetectionResult.passed(), DetectionResult.passed()]).status, TestStatus.PASS)

    def test_mixed_pass_inconclusive(self) -> None:
        results = [DetectionResult.passed(), DetectionResult.inconclusive("meh")]
        self.assertIs(combine(results).status, TestStatus.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
