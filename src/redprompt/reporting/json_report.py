"""JSON report: the full structured export of a scan."""

from __future__ import annotations

import json
from typing import Any

from redprompt.reporting.data import ReportData


def build_json(report: ReportData) -> dict[str, Any]:
    return report.to_dict()


def render_json(report: ReportData, *, indent: int = 2) -> str:
    return json.dumps(build_json(report), indent=indent, default=str)
