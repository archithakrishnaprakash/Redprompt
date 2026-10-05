"""Offline tests for the pure regression comparison."""

from __future__ import annotations

import unittest

from redprompt.regression import ScanSnapshot, compare_snapshots


class TestCompareSnapshots(unittest.TestCase):
    def test_baseline(self) -> None:
        current = ScanSnapshot("s1", {"RP-PROMPT-001": "high", "RP-DATA-001": "critical"})
        report = compare_snapshots(None, current)
        self.assertEqual(report.verdict, "baseline")
        self.assertEqual(set(report.new), {"RP-PROMPT-001", "RP-DATA-001"})

    def test_improved(self) -> None:
        prev = ScanSnapshot("s1", {"RP-PROMPT-001": "high", "RP-DATA-001": "critical"})
        curr = ScanSnapshot("s2", {"RP-DATA-001": "medium"})
        report = compare_snapshots(prev, curr)
        self.assertEqual(report.verdict, "improved")
        self.assertIn("RP-PROMPT-001", report.resolved)
        self.assertIn("RP-DATA-001", report.unchanged)

    def test_regressed(self) -> None:
        prev = ScanSnapshot("s1", {"RP-PROMPT-001": "low"})
        curr = ScanSnapshot("s2", {"RP-PROMPT-001": "low", "RP-AGENT-002": "critical"})
        report = compare_snapshots(prev, curr)
        self.assertEqual(report.verdict, "regressed")
        self.assertIn("RP-AGENT-002", report.new)

    def test_unchanged(self) -> None:
        prev = ScanSnapshot("s1", {"RP-PROMPT-001": "high"})
        curr = ScanSnapshot("s2", {"RP-PROMPT-001": "high"})
        report = compare_snapshots(prev, curr)
        self.assertEqual(report.verdict, "unchanged")

    def test_severity_delta(self) -> None:
        prev = ScanSnapshot("s1", {"a": "high", "b": "high"})
        curr = ScanSnapshot("s2", {"a": "high"})
        report = compare_snapshots(prev, curr)
        self.assertEqual(report.severity_delta["high"], -1)

    def test_weighted_score(self) -> None:
        snap = ScanSnapshot("s", {"a": "critical", "b": "low"})
        # critical rank 4 + low rank 1 = 5
        self.assertEqual(snap.weighted_score(), 5)


if __name__ == "__main__":
    unittest.main()
