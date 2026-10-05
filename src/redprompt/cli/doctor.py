"""``redprompt doctor`` — environment and configuration diagnostics.

The check logic is deliberately separated from rendering so it can be unit
tested without a terminal. Each check returns a :class:`CheckResult`; the command
renders them and exits non-zero if any check FAILs.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sqlalchemy import text

from redprompt.core.context import AppContext

MIN_PYTHON = (3, 11)


class CheckStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str


def _check_python() -> CheckResult:
    version = sys.version_info
    ok = (version.major, version.minor) >= MIN_PYTHON
    detail = f"{version.major}.{version.minor}.{version.micro}"
    if ok:
        return CheckResult("Python", CheckStatus.PASS, detail)
    return CheckResult(
        "Python", CheckStatus.FAIL, f"{detail} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"
    )


def _check_configuration(ctx: AppContext) -> CheckResult:
    path = ctx.settings.config_path
    if path is None:
        return CheckResult(
            "Configuration", CheckStatus.WARN, "no .redprompt.yml found; using defaults"
        )
    return CheckResult("Configuration", CheckStatus.PASS, str(path))


def _check_database(ctx: AppContext) -> CheckResult:
    try:
        with ctx.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return CheckResult("Database", CheckStatus.PASS, ctx.settings.database_url)
    except Exception as exc:  # noqa: BLE001 - diagnostics must report, not raise
        return CheckResult("Database", CheckStatus.FAIL, f"cannot connect: {exc}")


def _check_permissions(ctx: AppContext) -> CheckResult:
    out_dir = Path(ctx.settings.output.directory)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=out_dir, delete=True):
            pass
        return CheckResult("Permissions", CheckStatus.PASS, f"writable: {out_dir}/")
    except OSError as exc:
        return CheckResult("Permissions", CheckStatus.FAIL, f"cannot write {out_dir}/: {exc}")


def _check_optional_deps() -> CheckResult:
    optional = {"fastapi": "dashboard/API", "uvicorn": "API server", "weasyprint": "PDF reports"}
    missing = [f"{mod} ({why})" for mod, why in optional.items() if importlib.util.find_spec(mod) is None]
    if not missing:
        return CheckResult("Optional deps", CheckStatus.PASS, "all present")
    return CheckResult("Optional deps", CheckStatus.WARN, "missing: " + ", ".join(missing))


def _check_provider_config() -> CheckResult:
    """Report which provider credentials are visible (never print their values)."""
    env_keys = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_HOST")
    present = [k for k in env_keys if os.environ.get(k)]
    if present:
        return CheckResult("Providers", CheckStatus.PASS, "configured: " + ", ".join(present))
    return CheckResult(
        "Providers", CheckStatus.WARN, "no provider env vars set (lab targets need none)"
    )


def _check_proxy(ctx: AppContext) -> CheckResult:
    # Phase 7 wires the inspection proxy; for now report redaction posture.
    posture = "redaction on" if ctx.settings.security.redact_secrets else "redaction OFF"
    status = CheckStatus.PASS if ctx.settings.security.redact_secrets else CheckStatus.WARN
    return CheckResult("Proxy/redaction", status, posture)


def _check_docker() -> CheckResult:
    if shutil.which("docker"):
        return CheckResult("Docker", CheckStatus.PASS, "docker CLI available (lab ready)")
    return CheckResult("Docker", CheckStatus.WARN, "docker not found (lab uses docker compose)")


def _check_safety(ctx: AppContext) -> CheckResult:
    s = ctx.settings.safety
    if s.require_authorization and s.block_public_targets:
        return CheckResult("Safety controls", CheckStatus.PASS, "authorized + local-only enforced")
    return CheckResult(
        "Safety controls",
        CheckStatus.WARN,
        "authorization or public-target blocking is disabled",
    )


def run_doctor(ctx: AppContext) -> list[CheckResult]:
    """Run all diagnostics and return their results."""
    return [
        _check_python(),
        _check_configuration(ctx),
        _check_database(ctx),
        _check_permissions(ctx),
        _check_safety(ctx),
        _check_provider_config(),
        _check_proxy(ctx),
        _check_optional_deps(),
        _check_docker(),
    ]


def worst_status(results: list[CheckResult]) -> CheckStatus:
    if any(r.status is CheckStatus.FAIL for r in results):
        return CheckStatus.FAIL
    if any(r.status is CheckStatus.WARN for r in results):
        return CheckStatus.WARN
    return CheckStatus.PASS
