"""Write report files (JSON / SARIF / HTML / PDF) to disk."""

from __future__ import annotations

import json
from pathlib import Path

from redprompt.reporting.data import ReportData
from redprompt.reporting.html import render_html, render_pdf
from redprompt.reporting.json_report import render_json
from redprompt.reporting.sarif import build_sarif


def generate_reports(
    report: ReportData, formats: list[str], out_dir: str | Path
) -> dict[str, str]:
    """Write the requested report formats; return {format: path} (pdf omitted if unavailable)."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    base = f"assessment-{report.scan.get('scan_uuid', 'scan')[:8]}"
    written: dict[str, str] = {}

    if "json" in formats:
        path = directory / f"{base}.json"
        path.write_text(render_json(report), encoding="utf-8")
        written["json"] = str(path)

    if "sarif" in formats:
        path = directory / f"{base}.sarif"
        path.write_text(json.dumps(build_sarif(report), indent=2), encoding="utf-8")
        written["sarif"] = str(path)

    if "html" in formats:
        path = directory / f"{base}.html"
        path.write_text(render_html(report), encoding="utf-8")
        written["html"] = str(path)

    if "pdf" in formats:
        path = directory / f"{base}.pdf"
        if render_pdf(report, str(path)):
            written["pdf"] = str(path)
        # else: WeasyPrint not installed; silently skip (caller can warn).

    return written
