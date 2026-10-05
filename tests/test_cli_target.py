"""CLI tests for the `target` command group."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from redprompt.cli.main import app

runner = CliRunner()


def _cfg(tmp_path: Path) -> list[str]:
    cfg = tmp_path / ".redprompt.yml"
    cfg.write_text(f"database_url: sqlite:///{tmp_path / 'cli.db'}\n")
    return ["--config", str(cfg)]


def test_add_list_show_remove(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    r = runner.invoke(
        app,
        [*base, "target", "add", "-n", "lab", "-u", "http://127.0.0.1:8000", "--authorized"],
    )
    assert r.exit_code == 0, r.stdout
    assert "Registered target" in r.stdout
    assert "in scope" in r.stdout

    r = runner.invoke(app, [*base, "target", "list"])
    assert r.exit_code == 0
    assert "lab" in r.stdout

    r = runner.invoke(app, [*base, "target", "show", "lab"])
    assert r.exit_code == 0
    assert "127.0.0.1" in r.stdout

    r = runner.invoke(app, [*base, "target", "remove", "lab", "--yes"])
    assert r.exit_code == 0
    assert "Removed" in r.stdout


def test_add_public_target_warns_not_scannable(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    r = runner.invoke(
        app,
        [*base, "target", "add", "-n", "ext", "-u", "https://api.example.com", "--authorized"],
    )
    assert r.exit_code == 0
    assert "NOT yet scannable" in r.stdout


def test_add_unauthorized_hint(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    r = runner.invoke(app, [*base, "target", "add", "-n", "lab2", "-u", "http://127.0.0.1:9000"])
    assert r.exit_code == 0
    assert "--authorized" in r.stdout


def test_invalid_url_rejected(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    r = runner.invoke(app, [*base, "target", "add", "-n", "bad", "-u", "127.0.0.1:8000"])
    assert r.exit_code == 2


def test_duplicate_name(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    runner.invoke(app, [*base, "target", "add", "-n", "dup", "-u", "http://127.0.0.1:8000", "--authorized"])
    r = runner.invoke(app, [*base, "target", "add", "-n", "dup", "-u", "http://127.0.0.1:8000", "--authorized"])
    assert r.exit_code == 1
    assert "already exists" in r.stdout


def test_profile_shows_surface(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    runner.invoke(app, [*base, "target", "add", "-n", "lab", "-u", "http://127.0.0.1:8000",
                        "--type", "agent", "--agent", "--authorized"])
    r = runner.invoke(app, [*base, "profile", "lab"])
    assert r.exit_code == 0
    assert "Application Profile" in r.stdout
    assert "agent" in r.stdout
    assert "configured" in r.stdout  # honest source labelling
