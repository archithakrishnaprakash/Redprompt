"""``redprompt report`` and ``redprompt gate`` commands."""

from __future__ import annotations

import uuid
from typing import Optional

import typer
from rich.console import Console

from redprompt.core.context import AppContext
from redprompt.db.models import Report, Scan
from redprompt.exceptions import RedPromptError
from redprompt.reporting.builder import ReportBuilder
from redprompt.reporting.data import ReportData
from redprompt.reporting.gate import evaluate_gate
from redprompt.reporting.generate import generate_reports
from redprompt.targets.service import TargetService

console = Console()
err_console = Console(stderr=True)


def _ctx(ctx: typer.Context) -> AppContext:
    return ctx.obj


def _build_report(app_ctx: AppContext, target: str, scan_uuid: Optional[str]) -> tuple[ReportData, int | None, int | None]:
    with app_ctx.session() as s:
        builder = ReportBuilder(s)
        if scan_uuid:
            data = builder.for_scan(scan_uuid)
            scan = s.query(Scan).filter_by(scan_uuid=scan_uuid).one()
            return data, scan.id, scan.target_id
        target_id = TargetService(s).get(target).id
        data = builder.latest_for_target(target_id)
        scan = s.query(Scan).filter_by(scan_uuid=data.scan["scan_uuid"]).one()
        return data, scan.id, target_id


def report_command(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id (uses its latest scan)."),
    fmt: list[str] = typer.Option([], "--format", "-f", help="json|sarif|html|pdf (repeatable)."),
    out: Optional[str] = typer.Option(None, "--out", help="Output directory."),
    scan_uuid: Optional[str] = typer.Option(None, "--scan", help="Report a specific scan uuid."),
) -> None:
    """Generate an assessment report in one or more formats."""
    app_ctx = _ctx(ctx)
    formats = list(fmt) or app_ctx.settings.output.formats
    out_dir = out or app_ctx.settings.output.directory
    try:
        data, scan_id, target_id = _build_report(app_ctx, target, scan_uuid)
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    written = generate_reports(data, formats, out_dir)
    if "pdf" in formats and "pdf" not in written:
        console.print("[yellow]PDF skipped:[/] install the 'pdf' extra (WeasyPrint) to enable it.")

    with app_ctx.session() as s:
        s.add(
            Report(
                report_uuid=str(uuid.uuid4()),
                scan_id=scan_id,
                target_id=target_id,
                formats=list(written),
                path=out_dir,
                summary=data.severity_counts(),
            )
        )

    console.print("[green]Report generated:[/]")
    for f, path in written.items():
        console.print(f"  {f.upper():5} → {path}")


def gate_command(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id (uses its latest scan)."),
    fail_on: str = typer.Option("high", "--fail-on", help="critical|high|medium|low|info."),
    scan_uuid: Optional[str] = typer.Option(None, "--scan", help="Gate a specific scan uuid."),
) -> None:
    """CI security gate: exit non-zero if findings meet/exceed the threshold."""
    app_ctx = _ctx(ctx)
    try:
        data, _, _ = _build_report(app_ctx, target, scan_uuid)
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    result = evaluate_gate(data, fail_on)
    if result.passed:
        console.print(f"[green]{result.message()}[/]")
    else:
        err_console.print(f"[bold red]{result.message()}[/]")
    raise typer.Exit(code=result.exit_code)
