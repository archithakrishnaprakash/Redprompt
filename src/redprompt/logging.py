"""Structured logging for RedPrompt.

Uses ``structlog`` so every log line can carry machine-readable context
(``scan_id``, ``target_id``, ``test_id``, ``duration_ms`` ...). In interactive
use we render coloured key/value lines; in CI or when ``logging.json`` is set we
emit newline-delimited JSON suitable for log shippers.

A redaction processor (backed by the dependency-free :mod:`redprompt.redaction`
module) runs on *every* event so secrets never reach the logs, regardless of
which subsystem emitted them.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable
from typing import Any

import structlog

from redprompt.redaction import SENSITIVE_KEYS, REDACTION, redact_text


def _redact_processor(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key, val in list(event_dict.items()):
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = REDACTION
        elif isinstance(val, str):
            event_dict[key] = redact_text(val)
    return event_dict


def configure_logging(level: str = "INFO", *, json_logs: bool = False) -> None:
    """Configure structlog + stdlib logging. Idempotent."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=numeric_level,
        force=True,
    )

    shared_processors: Iterable[Any] = (
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_processor,
        structlog.processors.StackInfoRenderer(),
    )

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None, **initial: Any) -> Any:
    """Return a bound logger, optionally with initial context."""
    logger = structlog.get_logger(name)
    if initial:
        logger = logger.bind(**initial)
    return logger
