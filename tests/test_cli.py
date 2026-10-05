"""Tests for the CLI (version, doctor, config) via Typer's CliRunner."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from redprompt.cli.main import app
from redprompt.version import get_version

runner = CliRunner()


def _write_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / ".redprompt.yml"
    cfg.write_text(
        f"database_url: sqlite:///{tmp_path / 'cli.db'}\n"
        f"output:\n  directory: {tmp_path / 'reports'}\n"
    )
    return cfg


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert get_version() in result.stdout


def test_doctor_runs_and_reports(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path)
    result = runner.invoke(app, ["--config", str(cfg), "doctor"])
    assert result.exit_code in (0, 1)  # WARN->0, FAIL->1; must not crash
    assert "RedPrompt Doctor" in result.stdout
    assert "Python" in result.stdout
    assert "Safety controls" in result.stdout


def test_doctor_database_check_passes(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path)
    result = runner.invoke(app, ["--config", str(cfg), "doctor"])
    assert "PASS" in result.stdout
    assert "Database" in result.stdout


def test_config_show(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path)
    result = runner.invoke(app, ["--config", str(cfg), "config", "show"])
    assert result.exit_code == 0
    assert "database_url" in result.stdout


def test_config_path(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path)
    result = runner.invoke(app, ["--config", str(cfg), "config", "path"])
    assert result.exit_code == 0
    assert str(cfg) in result.stdout


def test_bad_config_exits_2() -> None:
    result = runner.invoke(app, ["--config", "/no/such/file.yml", "doctor"])
    assert result.exit_code == 2


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code in (0, 2)
    assert "RedPrompt" in result.stdout
