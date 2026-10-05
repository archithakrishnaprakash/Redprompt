"""Shared domain vocabulary for RedPrompt.

Central enums keep terminology consistent across the database, orchestrator,
CLI, and reports, and give the type checker something concrete to enforce. All
are :class:`str` enums so they serialise cleanly to JSON/SARIF and store as
plain text in the database.
"""

from __future__ import annotations

from enum import StrEnum


class AppType(StrEnum):
    LLM = "llm"
    RAG = "rag"
    AGENT = "agent"
    API = "api"
    DOCUMENT = "document"


class AuthMethod(StrEnum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"


class Category(StrEnum):
    PROMPT = "prompt"
    DATA = "data"
    RAG = "rag"
    AGENT = "agent"
    API = "api"
    FILE = "file"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher = more severe. Useful for sorting and gate thresholds."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Exploitability(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TestStatus(StrEnum):
    """Outcome of a single security-test execution."""

    PASS = "pass"          # target behaved securely
    FAIL = "fail"          # a weakness was detected
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"        # the test itself failed to run
    SKIPPED = "skipped"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class FindingStatus(StrEnum):
    OPEN = "open"
    REMEDIATED = "remediated"
    RETEST_REQUIRED = "retest_required"
    STILL_VULNERABLE = "still_vulnerable"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class RetestStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"
    AVAILABLE = "available"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class DetectionSource(StrEnum):
    """How a piece of attack-surface knowledge was established.

    We never claim ``DETECTED`` unless RedPrompt actually verified it.
    """

    DETECTED = "detected"
    CONFIGURED = "configured"
    USER_PROVIDED = "user_provided"
    UNKNOWN = "unknown"


class SurfaceStatus(StrEnum):
    DISCOVERED = "discovered"
    TESTED = "tested"
    UNTESTED = "untested"
    VULNERABLE = "vulnerable"


class Confidence:
    """Named confidence thresholds (kept as a namespace, not an enum)."""

    LOW = 0.40
    MEDIUM = 0.70
    HIGH = 0.90
