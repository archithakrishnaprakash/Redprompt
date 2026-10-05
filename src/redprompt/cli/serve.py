"""``redprompt serve`` — run the REST API + dashboard."""

from __future__ import annotations

import os
from typing import Optional

import typer
from rich.console import Console

from redprompt.core.context import AppContext

console = Console()
err_console = Console(stderr=True)


def serve_command(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (default: loopback)."),
    port: int = typer.Option(8080, "--port", help="Bind port."),
    token: Optional[str] = typer.Option(
        None, "--token", help="Bearer token to protect the API (or REDPROMPT_DASHBOARD_TOKEN)."
    ),
) -> None:
    """Serve the RedPrompt dashboard and REST API (needs the 'api' extra)."""
    app_ctx: AppContext = ctx.obj
    try:
        import uvicorn

        from redprompt.api.app import create_app
    except ImportError as exc:
        err_console.print(
            "[bold red]The API requires the 'api' extra.[/] Install with: pip install -e '.[api]'"
        )
        raise typer.Exit(code=1) from exc

    resolved_token = token or os.environ.get("REDPROMPT_DASHBOARD_TOKEN")
    if not resolved_token and host not in ("127.0.0.1", "localhost", "::1"):
        err_console.print("[bold red]Refusing to bind a non-loopback host without a --token.[/]")
        raise typer.Exit(code=2)
    if not resolved_token:
        console.print("[yellow]Warning:[/] no token set — the API is open (local use only).")

    app = create_app(app_ctx, token=resolved_token)
    console.print(f"[green]RedPrompt dashboard[/] → http://{host}:{port}  (docs at /docs)")
    uvicorn.run(app, host=host, port=port, log_level=app_ctx.settings.logging.level.lower())
