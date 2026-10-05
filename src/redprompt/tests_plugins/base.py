"""Plugin base classes and DTOs for security tests.

``TargetInfo`` is a lightweight, ORM-independent snapshot of a target so tests and
the scan engine never import SQLAlchemy — keeping the test framework a pure port
that is testable without a database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from redprompt.analysis.base import DetectionResult
from redprompt.enums import Category, Exploitability, Severity, TestStatus
from redprompt.providers.base import ProviderRequest

if TYPE_CHECKING:  # avoid importing heavy modules at runtime for pure consumers
    from redprompt.config import Settings
    from redprompt.providers.base import ModelProvider


@dataclass
class TargetInfo:
    """ORM-independent snapshot of a target passed to tests."""

    name: str
    base_url: str
    app_type: str = "llm"
    auth_method: str = "none"
    authorized: bool = False
    rag_enabled: bool = False
    agent_enabled: bool = False
    file_upload: bool = False
    streaming: bool = False
    tools: list[str] = field(default_factory=list)
    environment: str = "local"
    tags: list[str] = field(default_factory=list)


@dataclass
class TestContext:
    target: TargetInfo
    provider: "ModelProvider"
    settings: "Settings"
    dry_run: bool = False
    logger: Any = None


@dataclass
class ProbeRecord:
    """One request/response/detection triple captured during a test."""

    label: str
    request: dict[str, Any]
    response: dict[str, Any]
    detection: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    test_id: str
    status: TestStatus
    confidence: float
    severity: Severity
    reason: str = ""
    indicators: list[str] = field(default_factory=list)
    probes: list[ProbeRecord] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0

    @property
    def is_finding(self) -> bool:
        return self.status is TestStatus.FAIL


class SecurityTest(ABC):
    """Base class for all security tests.

    Subclasses set class attributes (``id``, ``name``, ``category`` ...) and
    implement :meth:`execute`. ``applies_to`` lets a test opt out of irrelevant
    targets (e.g. an agent test on a plain LLM). ``heuristic`` and ``experimental``
    are surfaced honestly in findings/reports.
    """

    id: str = ""
    name: str = ""
    category: Category = Category.PROMPT
    severity: Severity = Severity.MEDIUM
    description: str = ""
    references: list[str] = []
    experimental: bool = False
    heuristic: bool = True
    version: str = "0.1.0"

    # Risk inputs (see redprompt.risk). Sensible defaults; override per test.
    exploitability: Exploitability = Exploitability.MEDIUM
    persistent: bool = False
    requires_privilege: bool = False
    impact: str = ""

    def applies_to(self, target: TargetInfo) -> bool:
        return True

    def remediation(self) -> str:
        return ""

    def impact_text(self) -> str:
        return self.impact or (
            f"A successful {self.category.value} weakness of this kind can compromise "
            "confidentiality, integrity, or the intended behaviour of the AI application."
        )

    @abstractmethod
    async def execute(self, ctx: TestContext) -> TestResult:
        """Run the test and return a :class:`TestResult`."""

    # -- convenience builders ------------------------------------------------
    def result(
        self,
        detection: DetectionResult,
        *,
        probes: list[ProbeRecord] | None = None,
        severity: Severity | None = None,
    ) -> TestResult:
        return TestResult(
            test_id=self.id,
            status=detection.status,
            confidence=detection.confidence,
            severity=severity or self.severity,
            reason=detection.reason,
            indicators=list(detection.indicators),
            probes=probes or [],
        )

    def error_result(self, message: str, probes: list[ProbeRecord] | None = None) -> TestResult:
        return TestResult(
            test_id=self.id,
            status=TestStatus.ERROR,
            confidence=0.0,
            severity=self.severity,
            reason=message,
            probes=probes or [],
            error=message,
        )

    def skipped_result(self, reason: str) -> TestResult:
        return TestResult(
            test_id=self.id,
            status=TestStatus.SKIPPED,
            confidence=0.0,
            severity=self.severity,
            reason=reason,
        )

    def as_metadata(self) -> dict[str, Any]:
        return {
            "test_id": self.id,
            "name": self.name,
            "category": self.category.value,
            "default_severity": self.severity.value,
            "description": self.description,
            "references": list(self.references),
            "experimental": self.experimental,
            "heuristic": self.heuristic,
            "version": self.version,
            "exploitability": self.exploitability.value,
            "persistent": self.persistent,
            "requires_privilege": self.requires_privilege,
        }


def make_probe_record(
    label: str,
    spec: Any,
    provider_response: Any,
    detection: DetectionResult,
) -> ProbeRecord:
    """Build a ProbeRecord from a request spec + provider response + detection.

    The stored request/response are structured dicts; redaction is applied later
    by the evidence subsystem before persistence.
    """
    request: dict[str, Any] = {}
    if spec is not None:
        request = {
            "method": getattr(spec, "method", None),
            "url": getattr(spec, "url", None),
            "headers": getattr(spec, "headers", {}),
            "body": getattr(spec, "json_body", None),
        }
    response: dict[str, Any] = {}
    if provider_response is not None:
        response = {
            "status_code": getattr(provider_response, "status_code", None),
            "latency_ms": getattr(provider_response, "latency_ms", None),
            "text": getattr(provider_response, "text", None),
            "finish_reason": getattr(provider_response, "finish_reason", None),
            "tool_calls": getattr(provider_response, "tool_calls", []),
        }
    return ProbeRecord(label=label, request=request, response=response, detection=detection.as_dict())


class SingleProbeTest(SecurityTest):
    """Base for tests that send one probe prompt and analyse the reply.

    Subclasses provide :attr:`probe_prompt` (or override :meth:`build_request`) and
    implement :meth:`analyze`. This removes boilerplate for the common case while
    keeping ``analyze`` a pure, unit-testable function.
    """

    probe_prompt: str = ""
    system_prompt: str | None = None

    def build_request(self, ctx: TestContext) -> ProviderRequest:
        return ProviderRequest.from_prompt(self.probe_prompt, system=self.system_prompt)

    def analyze(self, response_text: str, ctx: TestContext) -> DetectionResult:
        """Analyse the response text. Override this for text-only detection."""
        raise NotImplementedError

    def analyze_response(self, response: object, ctx: TestContext) -> DetectionResult:
        """Analyse the full provider response (status, tool_calls, text).

        Defaults to :meth:`analyze` on the text; override when a test needs the
        status code or tool calls (e.g. API tests).
        """
        return self.analyze(getattr(response, "text", "") or "", ctx)

    async def execute(self, ctx: TestContext) -> TestResult:
        if ctx.dry_run:
            return self.skipped_result("dry-run: probe not sent")
        request = self.build_request(ctx)
        try:
            response = await ctx.provider.generate(request)
        except Exception as exc:  # noqa: BLE001 - network/provider errors are ERROR, not FAIL
            return self.error_result(f"probe request failed: {exc}")

        detection = self.analyze_response(response, ctx)
        probe = make_probe_record(self.name or self.id, response.request, response, detection)
        return self.result(detection, probes=[probe])
