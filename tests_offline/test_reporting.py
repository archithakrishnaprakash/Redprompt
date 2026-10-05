"""Offline tests for report formatters (JSON/SARIF/HTML) and the CI gate."""

from __future__ import annotations

import unittest

from redprompt.reporting.data import FindingReport, ReportData
from redprompt.reporting.gate import evaluate_gate
from redprompt.reporting.html import render_html
from redprompt.reporting.json_report import build_json
from redprompt.reporting.sarif import build_sarif


def _report() -> ReportData:
    findings = [
        FindingReport(
            finding_id="RP-DATA-0001", test_id="RP-DATA-001", title="Secret leakage",
            category="data", severity="critical", confidence=0.95, risk_score=9.4, status="open",
            description="Leaked a credential.", remediation="Use a secrets manager.",
            references=["https://owasp.org/"], risk_explanation="Risk 9.4/10 → CRITICAL ...",
            evidence_count=1,
        ),
        FindingReport(
            finding_id="RP-PROMPT-0002", test_id="RP-PROMPT-001", title="Prompt injection",
            category="prompt", severity="medium", confidence=0.8, risk_score=5.5, status="open",
            evidence_count=2,
        ),
    ]
    return ReportData(
        tool_name="RedPrompt", tool_version="0.1.0", generated_at="2026-09-23T00:00:00Z",
        target={"name": "lab-rag", "base_url": "http://127.0.0.1:8001", "app_type": "rag",
                "provider": "generic", "rag_enabled": True, "agent_enabled": False, "environment": "local"},
        scan={"scan_uuid": "abcd1234-uuid", "status": "completed", "categories": ["data", "prompt"],
              "total_tests": 16, "passed": 12, "failed": 2, "inconclusive": 1, "errored": 0, "skipped": 1},
        findings=findings,
        regression={"verdict": "improved", "new": [], "resolved": ["RP-RAG-001"], "unchanged": []},
    )


class TestJSON(unittest.TestCase):
    def test_structure(self) -> None:
        d = build_json(_report())
        self.assertEqual(d["tool"]["name"], "RedPrompt")
        self.assertEqual(d["severity_counts"]["critical"], 1)
        self.assertEqual(len(d["findings"]), 2)
        # sorted most-severe first
        self.assertEqual(d["findings"][0]["severity"], "critical")


class TestSARIF(unittest.TestCase):
    def test_schema_and_results(self) -> None:
        s = build_sarif(_report())
        self.assertEqual(s["version"], "2.1.0")
        driver = s["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "RedPrompt")
        rule_ids = {r["id"] for r in driver["rules"]}
        self.assertEqual(rule_ids, {"RP-DATA-001", "RP-PROMPT-001"})
        results = s["runs"][0]["results"]
        self.assertEqual(len(results), 2)

    def test_levels_and_security_severity(self) -> None:
        s = build_sarif(_report())
        by_rule = {r["ruleId"]: r for r in s["runs"][0]["results"]}
        self.assertEqual(by_rule["RP-DATA-001"]["level"], "error")     # critical
        self.assertEqual(by_rule["RP-PROMPT-001"]["level"], "warning")  # medium
        rule = next(r for r in s["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "RP-DATA-001")
        self.assertEqual(rule["properties"]["security-severity"], "9.4")

    def test_fingerprints(self) -> None:
        s = build_sarif(_report())
        fps = {r["partialFingerprints"]["redpromptFindingId"] for r in s["runs"][0]["results"]}
        self.assertIn("RP-DATA-0001", fps)


class TestHTML(unittest.TestCase):
    def test_renders_key_content(self) -> None:
        html = render_html(_report())
        self.assertIn("RedPrompt", html)
        self.assertIn("RP-DATA-0001", html)
        self.assertIn("Secret leakage", html)
        self.assertIn("Executive summary", html)
        self.assertIn("Authorized assessment", html)
        self.assertIn("badge b-critical", html)


class TestGate(unittest.TestCase):
    def test_fail_on_high_trips_on_critical(self) -> None:
        result = evaluate_gate(_report(), "high")
        self.assertFalse(result.passed)
        self.assertIn("RP-DATA-0001", result.offending)
        self.assertEqual(result.exit_code, 1)

    def test_fail_on_critical_ignores_medium(self) -> None:
        # remove the critical finding -> only medium remains
        report = _report()
        report.findings = [f for f in report.findings if f.severity != "critical"]
        result = evaluate_gate(report, "critical")
        self.assertTrue(result.passed)
        self.assertEqual(result.exit_code, 0)

    def test_fail_on_medium_trips(self) -> None:
        self.assertFalse(evaluate_gate(_report(), "medium").passed)


if __name__ == "__main__":
    unittest.main()
