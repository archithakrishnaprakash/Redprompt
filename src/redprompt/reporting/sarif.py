"""SARIF 2.1.0 output for GitHub code-scanning / CI security workflows.

Each finding becomes a SARIF result keyed by its test id (the rule). AI-application
findings have no source-file location, so we attach a synthetic logical location
(the target) — enough for GitHub to ingest and de-duplicate via partial
fingerprints, without pretending a line of code is responsible.
"""

from __future__ import annotations

from typing import Any

from redprompt.enums import Severity
from redprompt.reporting.data import ReportData

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# SARIF levels: error / warning / note / none
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _level(severity: str) -> str:
    return _LEVEL.get(Severity(severity), "warning")


def _security_severity(risk_score: float) -> str:
    # GitHub reads properties.security-severity (0.0-10.0) to bucket alerts.
    return f"{max(0.0, min(10.0, risk_score)):.1f}"


def build_sarif(report: ReportData) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    target_uri = f"redprompt://{report.target.get('name', 'target')}"

    for f in report.findings_sorted():
        if f.test_id not in rules:
            rules[f.test_id] = {
                "id": f.test_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "helpUri": f.references[0] if f.references else "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "help": {"text": f.remediation or "See references."},
                "defaultConfiguration": {"level": _level(f.severity)},
                "properties": {
                    "tags": ["ai-security", f.category],
                    "security-severity": _security_severity(f.risk_score),
                },
            }
        results.append(
            {
                "ruleId": f.test_id,
                "level": _level(f.severity),
                "message": {
                    "text": f"{f.title} ({f.severity}, risk {f.risk_score}/10): {f.risk_explanation or f.description}"
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {"name": report.target.get("name", "target"), "kind": "resource"}
                        ],
                        "physicalLocation": {
                            "artifactLocation": {"uri": target_uri},
                            "region": {"startLine": 1},
                        },
                    }
                ],
                "partialFingerprints": {"redpromptFindingId": f.finding_id},
                "properties": {
                    "confidence": round(f.confidence, 3),
                    "risk_score": f.risk_score,
                    "status": f.status,
                    "heuristic": f.heuristic,
                    "experimental": f.experimental,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool_name,
                        "version": report.tool_version,
                        "informationUri": "https://github.com/architha/redprompt",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target.get("name"),
                    "scan_uuid": report.scan.get("scan_uuid"),
                    "generated_at": report.generated_at,
                },
            }
        ],
    }
