"""HTML report rendering (Jinja2) and optional PDF conversion."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from redprompt.reporting.data import ReportData

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(report: ReportData) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(report=report)


def render_pdf(report: ReportData, path: str) -> bool:
    """Render a PDF via WeasyPrint if available. Returns False if unavailable."""
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:  # noqa: BLE001 - optional dependency
        return False
    HTML(string=render_html(report)).write_pdf(path)
    return True
