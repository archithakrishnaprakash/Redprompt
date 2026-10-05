"""Offline tests for the shared domain enums."""

from __future__ import annotations

import json
import unittest

from redprompt.enums import (
    Category,
    Confidence,
    FindingStatus,
    Severity,
    TestStatus,
)


class TestSeverity(unittest.TestCase):
    def test_rank_ordering(self) -> None:
        self.assertLess(Severity.LOW.rank, Severity.HIGH.rank)
        self.assertLess(Severity.HIGH.rank, Severity.CRITICAL.rank)
        self.assertEqual(Severity.INFO.rank, 0)

    def test_sort_by_rank(self) -> None:
        items = [Severity.MEDIUM, Severity.CRITICAL, Severity.LOW, Severity.HIGH]
        ordered = sorted(items, key=lambda s: s.rank, reverse=True)
        self.assertEqual(ordered[0], Severity.CRITICAL)
        self.assertEqual(ordered[-1], Severity.LOW)

    def test_str_value_serialisable(self) -> None:
        self.assertEqual(json.dumps({"sev": Severity.HIGH}), '{"sev": "high"}')


class TestEnumMembership(unittest.TestCase):
    def test_category_values(self) -> None:
        self.assertEqual(Category.PROMPT.value, "prompt")
        self.assertIn(Category.RAG, list(Category))

    def test_test_status_values(self) -> None:
        self.assertEqual(
            {s.value for s in TestStatus},
            {"pass", "fail", "inconclusive", "error", "skipped"},
        )

    def test_finding_status_values(self) -> None:
        self.assertIn(FindingStatus.STILL_VULNERABLE, list(FindingStatus))
        self.assertEqual(FindingStatus.OPEN.value, "open")


class TestConfidence(unittest.TestCase):
    def test_thresholds_ordered(self) -> None:
        self.assertLess(Confidence.LOW, Confidence.MEDIUM)
        self.assertLess(Confidence.MEDIUM, Confidence.HIGH)


if __name__ == "__main__":
    unittest.main()
