"""RedPrompt CLI entry point.

Only commands that are actually implemented are registered. Additional command
groups (``target``, ``scan``, ``findings`` ...) are added as their subsystems land
in later phases, so the CLI never advertises functionality that does not exist.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redprompt.cli.doctor import CheckStatus, run_doctor, worst_status
from redprompt.core.context import AppContext, build_context
from redprompt.exceptions import RedPromptError
from redprompt.version import get_version

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="redprompt",
    help=(
        "RedPrompt — AI Application Security Testing & Red Teaming Platform.\n\n"
        "For AUTHORIZED, controlled assessment of AI applications you own or are "
        "explicitly permitted to test. Ships with a local vulnerable lab."
    ),
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
)

config_app = typer.Typer(help="Inspect RedPrompt configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")

from redprompt.cli.target import target_app  # noqa: E402
from redprompt.cli.scan import scan_command, tests_command  # noqa: E402
from redprompt.cli.findings import (  # noqa: E402
    evidence_command,
    finding_command,
    findings_command,
)
from redprompt.cli.retest import regression_command, retest_command  # noqa: E402
from redprompt.cli.report import gate_command, report_command  # noqa: E402
from redprompt.cli.serve import serve_command  # noqa: E402
from redprompt.cli.profile import profile_command  # noqa: E402

app.add_typer(target_app, name="target")
app.command("profile")(profile_command)
app.command("scan")(scan_command)
app.command("tests")(tests_command)
app.command("findings")(findings_command)
app.command("finding")(finding_command)
app.command("evidence")(evidence_command)
app.command("retest")(retest_command)
app.command("regression")(regression_command)
app.command("report")(report_command)
app.command("gate")(gate_command)
app.command("serve")(serve_command)


def get_context(ctx: typer.Context) -> AppContext:
    """Return the AppContext built in the root callback."""
    obj = ctx.obj
    if not isinstance(obj, AppContext):  # pragma: no cover - defensive
        raise typer.Exit(code=2)
    return obj


@app.callback()
def main(
    ctx: typer.Context,
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to .redprompt.yml (default: auto-discover)."
    ),
) -> None:
    """Build the shared application context for all subcommands."""
    try:
        ctx.obj = build_context(config_path=config)
    except RedPromptError as exc:
        err_console.print(f"[bold red]Configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc


@app.command()
def version() -> None:
    """Show the RedPrompt version."""
    console.print(f"RedPrompt [bold cyan]{get_version()}[/]")


_STATUS_STYLE = {
    CheckStatus.PASS: "bold green",
    CheckStatus.WARN: "bold yellow",
    CheckStatus.FAIL: "bold red",
}


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Diagnose the environment, configuration, database, and safety posture."""
    app_ctx = get_context(ctx)
    results = run_doctor(app_ctx)

    table = Table(title="RedPrompt Doctor", title_style="bold", expand=False)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", style="white")

    for result in results:
        style = _STATUS_STYLE[result.status]
        table.add_row(result.name, f"[{style}]{result.status.value}[/]", result.detail)

    console.print(table)

    overall = worst_status(results)
    if overall is CheckStatus.FAIL:
        err_console.print("[bold red]Doctor found blocking problems.[/]")
        raise typer.Exit(code=1)
    if overall is CheckStatus.WARN:
        console.print("[yellow]Doctor completed with warnings.[/]")
    else:
        console.print("[green]All checks passed.[/]")


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Print the fully-resolved configuration (secrets are never stored here)."""
    app_ctx = get_context(ctx)
    settings = app_ctx.settings
    source = settings.config_path or "defaults (no .redprompt.yml found)"

    body = settings.model_dump_json(indent=2)
    console.print(Panel.fit(f"[dim]source:[/] {source}", title="config", border_style="cyan"))
    console.print_json(body)


@config_app.command("path")
def config_path(ctx: typer.Context) -> None:
    """Print the path of the active configuration file (if any)."""
    app_ctx = get_context(ctx)
    path = app_ctx.settings.config_path
    console.print(str(path) if path else "(no .redprompt.yml; using defaults)")


if __name__ == "__main__":  # pragma: no cover
    app()
