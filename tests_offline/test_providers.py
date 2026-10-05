"""Offline tests for provider adapters (pure build_request / parse_response)."""

from __future__ import annotations

import unittest

from redprompt.providers import build_provider
from redprompt.providers.base import (
    Message,
    ProviderRequest,
    TargetConnection,
    dotted_get,
    flatten_messages,
    split_system,
)


class _NoClient:
    """Placeholder client; pure methods never touch it."""


def _provider(name: str, **conn_kw):
    conn = TargetConnection(base_url="http://127.0.0.1:8000", **conn_kw)
    return build_provider(name, conn, _NoClient())  # type: ignore[arg-type]


class TestHelpers(unittest.TestCase):
    def test_split_system(self) -> None:
        msgs = [Message("system", "be safe"), Message("user", "hi")]
        system, rest = split_system(msgs)
        self.assertEqual(system, "be safe")
        self.assertEqual(len(rest), 1)

    def test_flatten_messages(self) -> None:
        out = flatten_messages([Message("user", "a"), Message("assistant", "b")])
        self.assertIn("user: a", out)
        self.assertIn("assistant: b", out)

    def test_dotted_get(self) -> None:
        data = {"a": {"b": [{"c": "found"}]}}
        self.assertEqual(dotted_get(data, "a.b.0.c"), "found")
        self.assertIsNone(dotted_get(data, "a.b.5.c"))
        self.assertIsNone(dotted_get(data, "x.y"))


class TestOpenAIProvider(unittest.TestCase):
    def test_build_request(self) -> None:
        p = _provider("openai", model="gpt-4o-mini", auth_method="bearer", auth_env="OPENAI_API_KEY")
        # credential resolved from env by factory; simulate one:
        p._credential = "sk-secret"
        spec = p.build_request(ProviderRequest.from_prompt("hello", max_tokens=50, temperature=0.2))
        self.assertEqual(spec.url, "http://127.0.0.1:8000/v1/chat/completions")
        self.assertEqual(spec.json_body["model"], "gpt-4o-mini")
        self.assertEqual(spec.json_body["messages"][-1], {"role": "user", "content": "hello"})
        self.assertEqual(spec.json_body["max_tokens"], 50)
        self.assertEqual(spec.headers["Authorization"], "Bearer sk-secret")

    def test_parse_response(self) -> None:
        p = _provider("openai")
        body = {
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": "hi there"}, "finish_reason": "stop"}],
        }
        text, meta = p.parse_response(200, body, {})
        self.assertEqual(text, "hi there")
        self.assertEqual(meta["finish_reason"], "stop")
        self.assertEqual(meta["model"], "gpt-4o-mini")


class TestAnthropicProvider(unittest.TestCase):
    def test_build_request_splits_system(self) -> None:
        p = _provider("anthropic", model="claude-3-haiku", auth_method="api_key", auth_env="ANTHROPIC_API_KEY")
        p._credential = "ak-secret"
        req = ProviderRequest.from_prompt("hi", system="be nice", max_tokens=100)
        spec = p.build_request(req)
        self.assertEqual(spec.url, "http://127.0.0.1:8000/v1/messages")
        self.assertEqual(spec.json_body["system"], "be nice")
        self.assertEqual(spec.json_body["max_tokens"], 100)
        self.assertNotIn("system", [m["role"] for m in spec.json_body["messages"]])
        self.assertEqual(spec.headers["x-api-key"], "ak-secret")
        self.assertEqual(spec.headers["anthropic-version"], "2023-06-01")

    def test_parse_response(self) -> None:
        p = _provider("anthropic")
        body = {"model": "claude-3-haiku", "content": [{"type": "text", "text": "hello"}], "stop_reason": "end_turn"}
        text, meta = p.parse_response(200, body, {})
        self.assertEqual(text, "hello")
        self.assertEqual(meta["finish_reason"], "end_turn")


class TestOllamaProvider(unittest.TestCase):
    def test_build_and_parse(self) -> None:
        p = _provider("ollama", model="llama3")
        spec = p.build_request(ProviderRequest.from_prompt("hey", temperature=0.1))
        self.assertEqual(spec.url, "http://127.0.0.1:8000/api/chat")
        self.assertEqual(spec.json_body["options"]["temperature"], 0.1)
        text, meta = p.parse_response(200, {"model": "llama3", "message": {"content": "yo"}, "done_reason": "stop"}, {})
        self.assertEqual(text, "yo")


class TestGenericProvider(unittest.TestCase):
    def test_default_shape(self) -> None:
        p = _provider("generic")
        spec = p.build_request(ProviderRequest.from_prompt("inject?"))
        self.assertEqual(spec.json_body, {"message": "inject?"})
        self.assertEqual(spec.url, "http://127.0.0.1:8000")

    def test_custom_field_and_path(self) -> None:
        p = _provider(
            "generic",
            endpoint="/chat",
            extra={"request_field": "q", "response_path": "data.reply", "extra_body": {"session": "x"}},
        )
        spec = p.build_request(ProviderRequest.from_prompt("hi"))
        self.assertEqual(spec.json_body, {"q": "hi", "session": "x"})
        self.assertEqual(spec.url, "http://127.0.0.1:8000/chat")
        text, meta = p.parse_response(200, {"data": {"reply": "hello!"}}, {})
        self.assertEqual(text, "hello!")

    def test_common_key_autodetect(self) -> None:
        p = _provider("generic")
        text, meta = p.parse_response(200, {"reply": "auto"}, {})
        self.assertEqual(text, "auto")
        self.assertEqual(meta["matched_key"], "reply")

    def test_unmatched_body_surfaced(self) -> None:
        p = _provider("generic")
        text, meta = p.parse_response(200, {"weird": {"nested": 1}}, {})
        self.assertTrue(meta.get("unmatched"))
        self.assertIn("weird", text)


class TestAuth(unittest.TestCase):
    def test_no_auth(self) -> None:
        p = _provider("openai", auth_method="none")
        self.assertEqual(p.auth_headers(), {})

    def test_bearer_without_credential(self) -> None:
        p = _provider("openai", auth_method="bearer", auth_env="MISSING")
        self.assertEqual(p.auth_headers(), {})  # no credential resolved


if __name__ == "__main__":
    unittest.main()
