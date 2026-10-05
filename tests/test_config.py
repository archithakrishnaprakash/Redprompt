"""Tests for configuration loading and precedence."""

from __future__ import annotations

from pathlib import Path

import pytest

from redprompt.config import (
    Settings,
    collect_env_overrides,
    find_config_file,
    load_settings,
)
from redprompt.exceptions import ConfigError


def test_defaults_are_valid() -> None:
    settings = load_settings(search=False)
    assert settings.database_url == "sqlite:///redprompt.db"
    assert settings.safety.require_authorization is True
    assert "prompt" in settings.scan.categories
    assert settings.risk.minimum_confidence == pytest.approx(0.70)


def test_yaml_is_loaded(tmp_path: Path) -> None:
    cfg = tmp_path / ".redprompt.yml"
    cfg.write_text("database_url: sqlite:///custom.db\nscan:\n  workers: 8\n")
    settings = load_settings(cfg)
    assert settings.database_url == "sqlite:///custom.db"
    assert settings.scan.workers == 8
    assert settings.config_path == cfg


def test_missing_explicit_config_raises() -> None:
    with pytest.raises(ConfigError):
        load_settings("/nonexistent/.redprompt.yml")


def test_invalid_yaml_root_raises(tmp_path: Path) -> None:
    cfg = tmp_path / ".redprompt.yml"
    cfg.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError):
        load_settings(cfg)


def test_env_overrides_file(tmp_path: Path) -> None:
    cfg = tmp_path / ".redprompt.yml"
    cfg.write_text("scan:\n  workers: 2\n")
    env = {"REDPROMPT_SCAN__WORKERS": "6", "REDPROMPT_DATABASE_URL": "sqlite:///env.db"}
    settings = load_settings(cfg, env=env)
    assert settings.scan.workers == 6
    assert settings.database_url == "sqlite:///env.db"


def test_explicit_overrides_win(tmp_path: Path) -> None:
    cfg = tmp_path / ".redprompt.yml"
    cfg.write_text("scan:\n  workers: 2\n")
    env = {"REDPROMPT_SCAN__WORKERS": "6"}
    settings = load_settings(cfg, env=env, overrides={"scan": {"workers": 10}})
    assert settings.scan.workers == 10


def test_collect_env_overrides_json_coercion() -> None:
    env = {
        "REDPROMPT_SCAN__WORKERS": "8",
        "REDPROMPT_OUTPUT__FORMATS": '["json","sarif"]',
        "REDPROMPT_DATABASE_URL": "sqlite:///x.db",
        "UNRELATED": "ignore-me",
    }
    result = collect_env_overrides(env)
    assert result["scan"]["workers"] == 8
    assert result["output"]["formats"] == ["json", "sarif"]
    assert result["database_url"] == "sqlite:///x.db"
    assert "unrelated" not in result


def test_invalid_category_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(search=False, overrides={"scan": {"categories": ["bogus"]}})


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(search=False, overrides={"logging": {"level": "LOUD"}})


def test_confidence_bounds_enforced() -> None:
    with pytest.raises(ConfigError):
        load_settings(search=False, overrides={"risk": {"minimum_confidence": 2.0}})


def test_find_config_file_walks_up(tmp_path: Path) -> None:
    (tmp_path / ".redprompt.yml").write_text("database_url: sqlite:///a.db\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    found = find_config_file(nested)
    assert found == tmp_path / ".redprompt.yml"


def test_settings_roundtrip_json() -> None:
    settings = Settings()
    payload = settings.model_dump_json()
    assert "database_url" in payload
