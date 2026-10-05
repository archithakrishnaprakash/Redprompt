"""``redprompt findings`` / ``finding`` / ``evidence`` commands."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redprompt.core.context import AppContext
from redprompt.exceptions import RedPromptError
from redprompt.findings import FindingService

console = Console()
err_console = Console(stderr=True)

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}


def _ctx(ctx: typer.Context) -> AppContext:
    return ctx.obj


def findings_command(
    ctx: typer.Context,
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity."),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status."),
) -> None:
    """List findings, most severe first."""
    app_ctx = _ctx(ctx)
    with app_ctx.session() as s:
        rows = FindingService(s).list(severity=severity, status=status)
        data = [
            (f.finding_id, f.severity.value, f.risk_score, f.confidence, f.status.value, f.title)
            for f in rows
        ]
    if not data:
        console.print("[dim]No findings.[/]")
        return
    table = Table(title="Findings")
    table.add_column("ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Risk", justify="right")
    table.add_column("Conf", justify="right")
    table.add_column("Status")
    table.add_column("Title")
    for fid, sev, risk, conf, status_v, title in data:
        table.add_row(
            fid, f"[{_SEV_STYLE.get(sev, 'white')}]{sev.upper()}[/]",
            f"{risk:.1f}", f"{conf:.0%}", status_v, title,
        )
    console.print(table)


def finding_command(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding ID, e.g. RP-PROMPT-0001."),
) -> None:
    """Show a finding in full, including its explainable risk breakdown."""
    app_ctx = _ctx(ctx)
    try:
        with app_ctx.session() as s:
            f = FindingService(s).get(finding_id)
            payload = {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category.value,
                "severity": f.severity.value,
                "risk_score": f.risk_score,
                "confidence": f.confidence,
                "status": f.status.value,
                "retest_status": f.retest_status.value,
                "description": f.description,
                "impact": f.impact,
                "exploitability": f.exploitability.value,
                "remediation": f.remediation,
                "references": f.references,
                "reproduction_steps": f.reproduction_steps,
                "risk_explanation": f.risk_factors.get("explanation", ""),
                "risk_factors": f.risk_factors,
            }
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    sev = payload["severity"]
    console.print(
        Panel.fit(
            f"[bold]{payload['finding_id']}[/]  "
            f"[{_SEV_STYLE.get(sev, 'white')}]{sev.upper()}[/]  "
            f"risk {payload['risk_score']:.1f}/10  conf {payload['confidence']:.0%}",
            title=payload["title"],
            border_style="cyan",
        )
    )
    console.print(f"[bold]Risk:[/] {payload['risk_explanation']}")
    console.print_json(data=payload)


def evidence_command(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding ID to show evidence for."),
) -> None:
    """Show the evidence timeline behind a finding (redacted, hash-verified)."""
    app_ctx = _ctx(ctx)
    from redprompt.evidence import verify_evidence

    try:
        with app_ctx.session() as s:
            rows = FindingService(s).evidence_for(finding_id)
            items = [
                {
                    "created_at": e.created_at.isoformat(),
                    "test_id": e.test_id,
                    "request": e.request,
                    "response": e.response,
                    "detection": e.detection_result,
                    "content_hash": e.content_hash,
                    "verified": verify_evidence(
                        {
                            "request": e.request,
                            "response": e.response,
                            "headers": e.headers,
                            "detection_result": e.detection_result,
                            "snippets": e.snippets,
                            "content_hash": e.content_hash,
                        }
                    ),
                }
                for e in rows
            ]
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if not items:
        console.print("[dim]No evidence recorded for this finding.[/]")
        return
    for i, item in enumerate(items, 1):
        badge = "[green]verified[/]" if item["verified"] else "[red]HASH MISMATCH[/]"
        console.print(f"\n[bold]Evidence #{i}[/] — {item['test_id']} — {item['created_at']} — {badge}")
        console.print_json(data=item)
