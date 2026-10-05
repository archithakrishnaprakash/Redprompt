"""Reporting engine: JSON, SARIF, HTML (and optional PDF) report generation."""

from __future__ import annotations

from redprompt.reporting.data import FindingReport, ReportData
from redprompt.reporting.gate import GateResult, evaluate_gate
from redprompt.reporting.json_report import build_json
from redprompt.reporting.sarif import build_sarif

__all__ = [
    "FindingReport",
    "GateResult",
    "ReportData",
    "build_json",
    "build_sarif",
    "evaluate_gate",
]
