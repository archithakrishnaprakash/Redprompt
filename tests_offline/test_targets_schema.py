"""Offline tests for target schemas and connection mapping (pure Pydantic)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from pydantic import ValidationError

from redprompt.enums import AppType, AuthMethod
from redprompt.targets.schemas import TargetCreate, connection_from_target


class TestTargetCreate(unittest.TestCase):
    def test_valid_minimal(self) -> None:
        t = TargetCreate(name="lab", base_url="http://127.0.0.1:8000")
        self.assertEqual(t.provider, "generic")
        self.assertEqual(t.app_type, AppType.LLM)
        self.assertFalse(t.authorized)

    def test_url_scheme_required(self) -> None:
        with self.assertRaises(ValidationError):
            TargetCreate(name="x", base_url="127.0.0.1:8000")

    def test_url_trailing_slash_stripped(self) -> None:
        t = TargetCreate(name="x", base_url="http://127.0.0.1:8000/")
        self.assertEqual(t.base_url, "http://127.0.0.1:8000")

    def test_unknown_provider_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            TargetCreate(name="x", base_url="http://127.0.0.1:8000", provider="madeup")

    def test_to_extra_carries_model_and_auth_env(self) -> None:
        t = TargetCreate(
            name="x",
            base_url="http://127.0.0.1:8000",
            model="gpt",
            auth_method=AuthMethod.BEARER,
            auth_env="OPENAI_API_KEY",
        )
        extra = t.to_extra()
        self.assertEqual(extra["model"], "gpt")
        self.assertEqual(extra["auth_env"], "OPENAI_API_KEY")

    def test_to_extra_never_holds_secret(self) -> None:
        # to_extra records only the env var NAME, never a credential value.
        t = TargetCreate(name="x", base_url="http://127.0.0.1:8000", auth_env="MY_KEY")
        self.assertNotIn("credential", t.to_extra())
        self.assertNotIn("token", t.to_extra())


class TestConnectionMapping(unittest.TestCase):
    def test_connection_from_target_like(self) -> None:
        row = SimpleNamespace(
            base_url="http://127.0.0.1:8000",
            api_endpoint="/chat",
            auth_method=AuthMethod.API_KEY,
            llm_provider="generic",
            extra={"auth_env": "K", "auth_header": "X-Api-Key", "model": "m", "response_path": "data.reply"},
        )
        conn = connection_from_target(row)
        self.assertEqual(conn.base_url, "http://127.0.0.1:8000")
        self.assertEqual(conn.endpoint, "/chat")
        self.assertEqual(conn.auth_method, "api_key")
        self.assertEqual(conn.auth_header, "X-Api-Key")
        self.assertEqual(conn.model, "m")
        self.assertEqual(conn.extra["response_path"], "data.reply")
        self.assertEqual(conn.url(), "http://127.0.0.1:8000/chat")


if __name__ == "__main__":
    unittest.main()
