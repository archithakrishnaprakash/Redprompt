"""``redprompt profile`` — application profiling / attack-surface summary.

Distinguishes what is *configured* (from target registration) from what is
*detected* (verified by an actual probe). We never claim detection we did not
verify: without ``--probe`` everything is labelled configured/user-provided.
"""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from redprompt.api.attack_surface import build_attack_surface
from redprompt.core.context import AppContext
from redprompt.exceptions import RedPromptError
from redprompt.providers import build_provider
from redprompt.providers.base import ProviderRequest
from redprompt.targets.schemas import connection_from_target
from redprompt.targets.service import TargetService, make_client

console = Console()
err_console = Console(stderr=True)

_STATUS_STYLE = {"vulnerable": "red", "tested": "green", "untested": "yellow", "discovered": "cyan"}


def _ctx(ctx: typer.Context) -> AppContext:
    return ctx.obj


async def _probe(app_ctx: AppContext, conn, provider_name: str) -> dict:
    client = make_client(app_ctx.settings)
    provider = build_provider(provider_name, conn, client)
    try:
        resp = await provider.generate(ProviderRequest.from_prompt("healthcheck"))
        return {"reachable": True, "status": resp.status_code, "latency_ms": resp.latency_ms}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}
    finally:
        await client.aclose()


def profile_command(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or id."),
    probe: bool = typer.Option(False, "--probe", help="Send one benign request to verify reachability."),
) -> None:
    """Profile a target's configured attack surface (optionally probe reachability)."""
    app_ctx = _ctx(ctx)
    try:
        with app_ctx.session() as s:
            t = TargetService(s).get(target)
            info = {
                "name": t.name, "base_url": t.base_url, "app_type": t.app_type.value,
                "provider": t.llm_provider, "auth_method": t.auth_method.value,
                "rag_enabled": t.rag_enabled, "agent_enabled": t.agent_enabled,
                "file_upload": t.file_upload, "streaming": t.streaming,
                "tools": [tool.name for tool in t.tools], "authorized": t.authorized,
            }
            conn = connection_from_target(t)
            provider_name = t.llm_provider or "generic"
            surface = build_attack_surface(
                app_type=t.app_type.value, rag_enabled=t.rag_enabled, agent_enabled=t.agent_enabled,
                file_upload=t.file_upload, auth_method=t.auth_method.value,
                tools=[tool.name for tool in t.tools],
            )
    except RedPromptError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.rule(f"[bold]RedPrompt Application Profile — {info['name']}")
    meta = Table(show_header=False)
    meta.add_column("k", style="cyan")
    meta.add_column("v")
    meta.add_column("src", style="dim")
    meta.add_row("Application type", info["app_type"], "configured")
    meta.add_row("Provider", info["provider"] or "-", "user-provided")
    meta.add_row("Authentication", info["auth_method"], "configured")
    meta.add_row("RAG", str(info["rag_enabled"]), "configured")
    meta.add_row("Agent / tools", f"{info['agent_enabled']} ({len(info['tools'])})", "configured")
    meta.add_row("File upload", str(info["file_upload"]), "configured")
    meta.add_row("Streaming", str(info["streaming"]), "configured")
    meta.add_row("Authorized", "yes" if info["authorized"] else "no", "user-provided")

    if probe:
        result = asyncio.run(_probe(app_ctx, conn, provider_name))
        if result.get("reachable"):
            meta.add_row("Reachability", f"HTTP {result['status']} ({result['latency_ms']}ms)", "DETECTED")
        else:
            meta.add_row("Reachability", f"unreachable: {result.get('error','')[:40]}", "DETECTED")
    else:
        meta.add_row("Reachability", "not probed (use --probe)", "unknown")
    console.print(meta)

    console.print("\n[bold]Detected surface[/] [dim](status from prior scans)[/]")
    surf = Table()
    surf.add_column("Component", style="cyan")
    surf.add_column("Label")
    surf.add_column("Status")
    for n in surface["nodes"]:
        style = _STATUS_STYLE.get(n["status"], "white")
        surf.add_row(n["component"], n["label"], f"[{style}]{n['status']}[/]")
    console.print(surf)
