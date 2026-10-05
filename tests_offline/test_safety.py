"""Offline tests for the engagement safety controls."""

from __future__ import annotations

import unittest

from redprompt.safety import (
    classify_ip,
    evaluate_target,
    extract_host,
    is_local_target,
)

DEFAULT_ALLOW = ["127.0.0.1", "localhost", "::1"]


def _eval(url: str, *, authorized: bool = True, block_public: bool = True, require_auth: bool = True):
    return evaluate_target(
        url,
        authorized=authorized,
        require_authorization=require_auth,
        block_public_targets=block_public,
        allowed_hosts=DEFAULT_ALLOW,
    )


class TestHostParsing(unittest.TestCase):
    def test_extract_host(self) -> None:
        self.assertEqual(extract_host("http://127.0.0.1:8000/chat"), "127.0.0.1")
        self.assertEqual(extract_host("https://Example.COM/x"), "example.com")
        self.assertEqual(extract_host("localhost:9000"), "localhost")

    def test_classify_ip(self) -> None:
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("10.0.0.5"), "private")
        self.assertEqual(classify_ip("169.254.1.1"), "link_local")
        self.assertEqual(classify_ip("8.8.8.8"), "public")
        self.assertIsNone(classify_ip("example.com"))


class TestEvaluateTarget(unittest.TestCase):
    def test_loopback_authorized_allowed(self) -> None:
        self.assertTrue(_eval("http://127.0.0.1:8000").allowed)

    def test_localhost_allowed(self) -> None:
        self.assertTrue(_eval("http://localhost:8001/chat").allowed)

    def test_private_ip_allowed(self) -> None:
        self.assertTrue(_eval("http://10.1.2.3:8000").allowed)

    def test_public_ip_blocked(self) -> None:
        decision = _eval("http://8.8.8.8")
        self.assertFalse(decision.allowed)
        self.assertTrue(any("public" in r for r in decision.reasons))

    def test_unknown_hostname_blocked(self) -> None:
        decision = _eval("https://api.example.com/v1/chat")
        self.assertFalse(decision.allowed)
        self.assertTrue(any("allow-list" in r for r in decision.reasons))

    def test_unauthorized_blocked(self) -> None:
        decision = _eval("http://127.0.0.1:8000", authorized=False)
        self.assertFalse(decision.allowed)
        self.assertTrue(any("authorized" in r for r in decision.reasons))

    def test_public_allowed_when_blocking_disabled(self) -> None:
        self.assertTrue(_eval("http://8.8.8.8", block_public=False).allowed)

    def test_empty_url(self) -> None:
        self.assertFalse(_eval("not a url").allowed)


class TestIsLocalTarget(unittest.TestCase):
    def test_local(self) -> None:
        self.assertTrue(is_local_target("http://127.0.0.1:8000", DEFAULT_ALLOW))
        self.assertTrue(is_local_target("http://192.168.1.10", DEFAULT_ALLOW))

    def test_remote(self) -> None:
        self.assertFalse(is_local_target("https://evil.example.com", DEFAULT_ALLOW))


if __name__ == "__main__":
    unittest.main()
