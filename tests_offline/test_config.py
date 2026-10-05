"""Offline tests for configuration loading and precedence (pydantic + yaml)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from redprompt.config import (
    Settings,
    collect_env_overrides,
    find_config_file,
    load_settings,
)
from redprompt.exceptions import ConfigError


class TestConfigDefaults(unittest.TestCase):
    def test_defaults_valid(self) -> None:
        s = load_settings(search=False)
        self.assertEqual(s.database_url, "sqlite:///redprompt.db")
        self.assertTrue(s.safety.require_authorization)
        self.assertIn("prompt", s.scan.categories)
        self.assertAlmostEqual(s.risk.minimum_confidence, 0.70)

    def test_settings_json_roundtrip(self) -> None:
        self.assertIn("database_url", Settings().model_dump_json())


class TestConfigLoading(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cfg(self, text: str) -> Path:
        p = self.tmp / ".redprompt.yml"
        p.write_text(text)
        return p

    def test_yaml_loaded(self) -> None:
        cfg = self._cfg("database_url: sqlite:///custom.db\nscan:\n  workers: 8\n")
        s = load_settings(cfg)
        self.assertEqual(s.database_url, "sqlite:///custom.db")
        self.assertEqual(s.scan.workers, 8)
        self.assertEqual(s.config_path, cfg)

    def test_missing_explicit_raises(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(self.tmp / "nope.yml")

    def test_invalid_root_raises(self) -> None:
        cfg = self._cfg("- a\n- b\n")
        with self.assertRaises(ConfigError):
            load_settings(cfg)

    def test_env_overrides_file(self) -> None:
        cfg = self._cfg("scan:\n  workers: 2\n")
        env = {"REDPROMPT_SCAN__WORKERS": "6", "REDPROMPT_DATABASE_URL": "sqlite:///env.db"}
        s = load_settings(cfg, env=env)
        self.assertEqual(s.scan.workers, 6)
        self.assertEqual(s.database_url, "sqlite:///env.db")

    def test_explicit_overrides_win(self) -> None:
        cfg = self._cfg("scan:\n  workers: 2\n")
        s = load_settings(cfg, env={"REDPROMPT_SCAN__WORKERS": "6"}, overrides={"scan": {"workers": 10}})
        self.assertEqual(s.scan.workers, 10)

    def test_find_config_walks_up(self) -> None:
        (self.tmp / ".redprompt.yml").write_text("database_url: sqlite:///a.db\n")
        nested = self.tmp / "x" / "y"
        nested.mkdir(parents=True)
        self.assertEqual(find_config_file(nested), self.tmp / ".redprompt.yml")


class TestConfigValidation(unittest.TestCase):
    def test_env_json_coercion(self) -> None:
        env = {
            "REDPROMPT_SCAN__WORKERS": "8",
            "REDPROMPT_OUTPUT__FORMATS": '["json","sarif"]',
            "UNRELATED": "x",
        }
        result = collect_env_overrides(env)
        self.assertEqual(result["scan"]["workers"], 8)
        self.assertEqual(result["output"]["formats"], ["json", "sarif"])
        self.assertNotIn("unrelated", result)

    def test_invalid_category_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(search=False, overrides={"scan": {"categories": ["bogus"]}})

    def test_invalid_log_level_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(search=False, overrides={"logging": {"level": "LOUD"}})

    def test_confidence_bounds(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(search=False, overrides={"risk": {"minimum_confidence": 2.0}})

    def test_invalid_format_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(search=False, overrides={"output": {"formats": ["docx"]}})


if __name__ == "__main__":
    unittest.main()
