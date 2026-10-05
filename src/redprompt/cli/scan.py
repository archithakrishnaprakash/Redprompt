"""``redprompt scan`` and ``redprompt tests`` commands."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from redprompt.core.context import AppContext
from redprompt.core.orchestrator import Orchestrator, ScanSummary
from redprompt.enums import TestStatus
from redprompt.exceptions import RedPromptError, SafetyViolation
from redprompt.proxy import TrafficInspector
from redprompt.tests_plugins.registry import build_registry

console = Console()
err_console = Console(stderr=True)


def _ctx(ctx: typer.Context) -> AppContext:
    return ctx.obj


def scan_command(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id."),
    category: list[str] = typer.Option([], "--category", help="Restrict to category (repeatable)."),
    test: list[str] = typer.Option([], "--test", help="Run specific test id(s) (repeatable)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Build the plan; send no traffic."),
    workers: Optional[int] = typer.Option(None, "--workers", help="Concurrency limit."),
    inspect: bool = typer.Option(False, "--inspect", help="Capture redacted request/response traffic."),
) -> None:
    """Run a security assessment against an authorized target."""
    app_ctx = _ctx(ctx)
    inspector = None
    if inspect:
        inspector = TrafficInspector(
            redact=app_ctx.settings.security.redact_secrets,
            store_body=app_ctx.settings.security.store_raw_traffic,
        )
    orch = Orchestrator(app_ctx, inspector=inspector)
    try:
        summary = asyncio.run(
            orch.run_scan(
                target,
                categories=list(category) or None,
                test_ids=list(test) or None,
                dry_run=dry_run,
                workers=workers,
            )
        )
    except SafetyViolation as exc:
        err_console.print(f"[bold red]Refused (safety):[/] {exc}")
        raise typer.Exit(code=2) from exc
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    _render_summary(summary)

    if inspector is not None:
        out_dir = Path(app_ctx.settings.output.directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"traffic-{summary.scan_uuid}.json"
        path.write_text(json.dumps(inspector.to_dict(), indent=2), encoding="utf-8")
        console.print(f"\n[dim]Captured {len(inspector)} requests → {path}[/]")
        console.print(f"[dim]Traffic summary: {inspector.summary()}[/]")


def _render_summary(summary: ScanSummary) -> None:
    console.rule("[bold]RedPrompt Security Assessment")
    console.print(f"Target:      [cyan]{summary.target_name}[/]")
    console.print(f"Scan:        {summary.scan_uuid}")
    console.print(f"Mode:        {'DRY-RUN (no traffic)' if summary.dry_run else 'live'}")
    console.print(f"Plan:        {summary.plan_size} tests")
    if not summary.safety.allowed and not summary.dry_run:
        console.print(f"[yellow]Safety:[/] {'; '.join(summary.safety.reasons)}")

    c = summary.counts
    table = Table(show_header=True, header_style="bold")
    for col in ("Executed", "Passed", "Failed", "Inconclusive", "Error", "Skipped"):
        table.add_column(col, justify="right")
    table.add_row(
        str(c["total"]),
        f"[green]{c[TestStatus.PASS.value]}[/]",
        f"[red]{c[TestStatus.FAIL.value]}[/]",
        str(c[TestStatus.INCONCLUSIVE.value]),
        str(c[TestStatus.ERROR.value]),
        str(c[TestStatus.SKIPPED.value]),
    )
    console.print(table)

    if summary.findings:
        console.print("\n[bold]Findings[/]")
        ftable = Table(show_header=True, header_style="bold")
        ftable.add_column("ID", style="cyan")
        ftable.add_column("Severity")
        ftable.add_column("Confidence", justify="right")
        ftable.add_column("Title")
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
        for f in sorted(summary.findings, key=lambda x: x.confidence, reverse=True):
            style = sev_style.get(f.severity, "white")
            ftable.add_row(f.finding_id, f"[{style}]{f.severity.upper()}[/]", f"{f.confidence:.0%}", f.title)
        console.print(ftable)
    else:
        console.print("\n[green]No findings.[/]")


def tests_command(
    ctx: typer.Context,
    category: Optional[str] = typer.Option(None, "--category", help="Filter by category."),
) -> None:
    """List the available security tests (the test library)."""
    registry = build_registry()
    tests = registry.by_category(category) if category else registry.all()

    if not tests:
        console.print("[dim]No tests registered.[/]")
        return

    table = Table(title="RedPrompt Test Library")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Name")
    table.add_column("Flags")
    for t in tests:
        flags = []
        if t.experimental:
            flags.append("experimental")
        if t.heuristic:
            flags.append("heuristic")
        table.add_row(t.id, t.category.value, t.severity.value, t.name, ", ".join(flags) or "-")
    console.print(table)
    console.print(f"\n[dim]{len(tests)} tests[/]")
