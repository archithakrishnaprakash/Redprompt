"""``redprompt target`` — register and manage authorized test targets."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from redprompt.core.context import AppContext
from redprompt.enums import AppType, AuthMethod
from redprompt.exceptions import RedPromptError
from redprompt.safety import evaluate_target
from redprompt.targets.schemas import TargetCreate, TargetView
from redprompt.targets.service import TargetService

console = Console()
err_console = Console(stderr=True)

target_app = typer.Typer(help="Register and manage authorized test targets.", no_args_is_help=True)


def _ctx(ctx: typer.Context) -> AppContext:
    return ctx.obj  # set by root callback


@target_app.command("add")
def add(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", "-n", help="Unique target name."),
    url: str = typer.Option(..., "--url", "-u", help="Base URL (http/https)."),
    endpoint: Optional[str] = typer.Option(None, "--endpoint", help="API path, e.g. /chat."),
    app_type: AppType = typer.Option(AppType.LLM, "--type", help="Application type."),
    provider: str = typer.Option("generic", "--provider", help="Wire protocol adapter."),
    model: Optional[str] = typer.Option(None, "--model", help="Model name (if applicable)."),
    auth_method: AuthMethod = typer.Option(AuthMethod.NONE, "--auth", help="Auth method."),
    auth_env: Optional[str] = typer.Option(
        None, "--auth-env", help="ENV VAR NAME holding the credential (never stored)."
    ),
    rag: bool = typer.Option(False, "--rag", help="RAG enabled."),
    agent: bool = typer.Option(False, "--agent", help="Agent/tools enabled."),
    file_upload: bool = typer.Option(False, "--file-upload", help="File upload supported."),
    streaming: bool = typer.Option(False, "--streaming", help="Streaming supported."),
    environment: str = typer.Option("local", "--env", help="Environment tag."),
    tag: list[str] = typer.Option([], "--tag", help="Repeatable tag."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirm you are AUTHORIZED to test this target."
    ),
) -> None:
    """Register a target. Only authorized, in-scope targets can be scanned."""
    app_ctx = _ctx(ctx)
    try:
        create = TargetCreate(
            name=name,
            base_url=url,
            api_endpoint=endpoint,
            app_type=app_type,
            provider=provider,
            model=model,
            auth_method=auth_method,
            auth_env=auth_env,
            rag_enabled=rag,
            agent_enabled=agent,
            file_upload=file_upload,
            streaming=streaming,
            environment=environment,
            tags=list(tag),
            authorized=authorized,
        )
    except Exception as exc:  # pydantic validation
        err_console.print(f"[bold red]Invalid target:[/] {exc}")
        raise typer.Exit(code=2) from exc

    # Surface the safety posture at registration time.
    s = app_ctx.settings.safety
    decision = evaluate_target(
        create.base_url,
        authorized=create.authorized,
        require_authorization=s.require_authorization,
        block_public_targets=s.block_public_targets,
        allowed_hosts=s.allowed_hosts,
    )

    try:
        with app_ctx.session() as session:
            svc = TargetService(session)
            target = svc.add(create)
            view = TargetView.model_validate(target)
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Registered target[/] [bold]{view.name}[/] (id={view.id})")
    if decision.allowed:
        console.print("[green]Scope check:[/] target is in scope and scannable.")
    else:
        console.print("[yellow]Scope check:[/] this target is NOT yet scannable:")
        for reason in decision.reasons:
            console.print(f"  [yellow]•[/] {reason}")
        if not create.authorized:
            console.print("  Re-run with [bold]--authorized[/] once you have permission.")


@target_app.command("list")
def list_targets(ctx: typer.Context) -> None:
    """List registered targets."""
    app_ctx = _ctx(ctx)
    with app_ctx.session() as session:
        targets = [TargetView.model_validate(t) for t in TargetService(session).list()]

    if not targets:
        console.print("[dim]No targets registered. Add one with `redprompt target add`.[/]")
        return

    table = Table(title="Targets")
    table.add_column("ID", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Provider")
    table.add_column("URL")
    table.add_column("Authorized")
    for t in targets:
        auth = "[green]yes[/]" if t.authorized else "[red]no[/]"
        table.add_row(str(t.id), t.name, t.app_type.value, t.llm_provider or "-", t.base_url, auth)
    console.print(table)


@target_app.command("show")
def show(ctx: typer.Context, target: str = typer.Argument(..., help="Target name or id.")) -> None:
    """Show a target's full configuration."""
    app_ctx = _ctx(ctx)
    try:
        with app_ctx.session() as session:
            view = TargetView.model_validate(TargetService(session).get(target))
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    console.print_json(view.model_dump_json(indent=2))


@target_app.command("remove")
def remove(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Remove a target and its associated data."""
    app_ctx = _ctx(ctx)
    if not yes and not typer.confirm(f"Remove target {target!r} and all its data?"):
        raise typer.Exit(code=0)
    try:
        with app_ctx.session() as session:
            TargetService(session).remove(target)
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Removed[/] {target}")


@target_app.command("authorize")
def authorize(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id."),
    revoke: bool = typer.Option(False, "--revoke", help="Revoke authorization instead."),
) -> None:
    """Mark a target as authorized for testing (or revoke)."""
    app_ctx = _ctx(ctx)
    try:
        with app_ctx.session() as session:
            t = TargetService(session).set_authorized(target, not revoke)
            name = t.name
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    state = "revoked" if revoke else "authorized"
    console.print(f"[green]Target {name} {state}.[/]")
