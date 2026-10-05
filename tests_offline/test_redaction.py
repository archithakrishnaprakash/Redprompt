"""Offline tests for the dependency-free redaction core."""

from __future__ import annotations

import unittest

from redprompt.redaction import (
    REDACTION,
    redact_headers,
    redact_text,
    redact_value,
)


class TestRedactText(unittest.TestCase):
    def test_bearer_token(self) -> None:
        out = redact_text("Authorization: Bearer sk-abcd1234efgh5678ijkl")
        self.assertNotIn("sk-abcd1234efgh5678ijkl", out)
        self.assertIn(REDACTION, out)

    def test_openai_key(self) -> None:
        self.assertNotIn("sk-", redact_text("key=sk-ABCDEFGHIJKLMNOPQRSTUVWX"))

    def test_github_token(self) -> None:
        self.assertNotIn("ghp_", redact_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))

    def test_aws_key(self) -> None:
        self.assertNotIn("AKIA", redact_text("AKIAIOSFODNN7EXAMPLE"))

    def test_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
        self.assertNotIn(jwt, redact_text(f"token {jwt}"))

    def test_private_key_header(self) -> None:
        self.assertIn(REDACTION, redact_text("-----BEGIN PRIVATE KEY-----"))

    def test_clean_text_unchanged(self) -> None:
        self.assertEqual(redact_text("nothing secret here"), "nothing secret here")

    def test_pii_email_only_when_requested(self) -> None:
        text = "contact me at alice@example.com"
        self.assertIn("alice@example.com", redact_text(text))  # default: keep
        self.assertNotIn("alice@example.com", redact_text(text, include_pii=True))

    def test_pii_card_like_digits(self) -> None:
        self.assertNotIn("4111 1111 1111 1111", redact_text("4111 1111 1111 1111", include_pii=True))


class TestRedactValue(unittest.TestCase):
    def test_sensitive_key_masked(self) -> None:
        data = {"authorization": "Bearer whatever", "note": "hello"}
        out = redact_value(data)
        self.assertEqual(out["authorization"], REDACTION)
        self.assertEqual(out["note"], "hello")

    def test_nested_structure(self) -> None:
        data = {"outer": {"api_key": "abc", "list": ["sk-ABCDEFGHIJKLMNOPQRST", "ok"]}}
        out = redact_value(data)
        self.assertEqual(out["outer"]["api_key"], REDACTION)
        self.assertNotIn("sk-ABCDEFGHIJKLMNOPQRST", out["outer"]["list"][0])
        self.assertEqual(out["outer"]["list"][1], "ok")

    def test_non_string_scalars_preserved(self) -> None:
        data = {"count": 3, "flag": True, "ratio": 0.5}
        self.assertEqual(redact_value(data), data)

    def test_redact_headers_case_insensitive(self) -> None:
        headers = {"Authorization": "Bearer x", "X-Api-Key": "secret", "Accept": "application/json"}
        out = redact_headers(headers)
        self.assertEqual(out["Authorization"], REDACTION)
        self.assertEqual(out["X-Api-Key"], REDACTION)
        self.assertEqual(out["Accept"], "application/json")


if __name__ == "__main__":
    unittest.main()
