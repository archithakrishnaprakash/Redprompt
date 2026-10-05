"""Tests for structured logging and secret redaction."""

from __future__ import annotations

from redprompt.logging import _redact_processor, configure_logging, get_logger
from redprompt.redaction import redact_text


def test_redact_bearer_token() -> None:
    text = "Authorization: Bearer sk-abcd1234efgh5678ijkl"
    redacted = redact_text(text)
    assert "sk-abcd1234efgh5678ijkl" not in redacted
    assert "«redacted»" in redacted


def test_redact_openai_style_key() -> None:
    assert "sk-" not in redact_text("key=sk-ABCDEFGHIJKLMNOPQRSTUVWX")


def test_redact_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
    assert jwt not in redact_text(f"token {jwt}")


def test_redact_processor_masks_sensitive_keys() -> None:
    event = {"event": "req", "authorization": "Bearer secretvalue123", "api_key": "abc"}
    out = _redact_processor(None, "info", dict(event))
    assert out["authorization"] == "«redacted»"
    assert out["api_key"] == "«redacted»"


def test_processor_redacts_secret_in_freetext_value() -> None:
    event = {"event": "response", "body": "here is sk-ABCDEFGHIJKLMNOPQRST and more"}
    out = _redact_processor(None, "info", dict(event))
    assert "sk-ABCDEFGHIJKLMNOPQRST" not in out["body"]


def test_get_logger_binds_context() -> None:
    configure_logging(level="INFO", json_logs=True)
    logger = get_logger("test", scan_id="abc")
    # Binding returns a logger; emitting should not raise.
    logger.info("hello", target_id=1)


def test_clean_text_unchanged() -> None:
    assert redact_text("nothing secret here") == "nothing secret here"
