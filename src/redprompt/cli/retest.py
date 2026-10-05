"""``redprompt retest`` and ``redprompt regression`` commands."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from redprompt.core.context import AppContext
from redprompt.exceptions import RedPromptError, SafetyViolation
from redprompt.regression import RegressionService
from redprompt.retest import RetestEngine
from redprompt.targets.service import TargetService

console = Console()
err_console = Console(stderr=True)

_VERDICT_STYLE = {"improved": "green", "regressed": "bold red", "unchanged": "yellow", "baseline": "cyan"}


def _ctx(ctx: typer.Context) -> AppContext:
    return ctx.obj


def retest_command(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding ID to retest, e.g. RP-PROMPT-0001."),
) -> None:
    """Re-run the test behind a finding and update its status."""
    app_ctx = _ctx(ctx)
    try:
        outcome = asyncio.run(RetestEngine(app_ctx).retest(finding_id))
    except SafetyViolation as exc:
        err_console.print(f"[bold red]Refused (safety):[/] {exc}")
        raise typer.Exit(code=2) from exc
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    style = {
        "remediated": "green",
        "still_vulnerable": "bold red",
        "retest_required": "yellow",
    }.get(outcome.new_status, "white")
    console.print(f"[bold]{outcome.finding_id}[/] retest #{outcome.retest_number}")
    console.print(f"  {outcome.previous_status} → [{style}]{outcome.new_status}[/]")
    console.print(f"  {outcome.explanation}")


def regression_command(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id."),
) -> None:
    """Compare a target's two most recent scans (security regression)."""
    app_ctx = _ctx(ctx)
    try:
        with app_ctx.session() as s:
            target_id = TargetService(s).get(target).id
            report = RegressionService(s).compare_latest(target_id)
    except (RedPromptError, ValueError) as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    verdict_style = _VERDICT_STYLE.get(report.verdict, "white")
    console.rule("[bold]Security Regression")
    console.print(f"Previous scan: {report.previous or '(none — baseline)'}")
    console.print(f"Current scan:  {report.current}")
    console.print(f"Verdict:       [{verdict_style}]{report.verdict.upper()}[/]")

    if report.previous:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Previous", justify="right")
        table.add_column("Current", justify="right")
        table.add_column("Δ", justify="right")
        for sev in ("critical", "high", "medium", "low", "info"):
            delta = report.severity_delta.get(sev, 0)
            dstr = f"+{delta}" if delta > 0 else str(delta)
            table.add_row(
                sev.upper(),
                str(report.previous_counts.get(sev, 0)),
                str(report.current_counts.get(sev, 0)),
                dstr,
            )
        console.print(table)
        console.print(f"[green]Resolved:[/] {len(report.resolved)}  "
                      f"[red]New:[/] {len(report.new)}  "
                      f"[yellow]Unchanged:[/] {len(report.unchanged)}")
        if report.new:
            console.print(f"  New: {', '.join(report.new)}")
        if report.resolved:
            console.print(f"  Resolved: {', '.join(report.resolved)}")
    else:
        console.print(f"Baseline scan with {len(report.new)} finding(s).")
