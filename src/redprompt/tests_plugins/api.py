"""AI API-security tests (auth enforcement, verbose errors, input validation).

These use the raw HTTP client (via the provider) so they can send malformed or
unauthenticated requests that the normal provider flow would not produce.
"""

from __future__ import annotations

from typing import Any

from redprompt.analysis.base import DetectionResult
from redprompt.analysis.detectors import detect_error_leakage, expected_status
from redprompt.enums import Category, Severity
from redprompt.providers.base import ProviderRequest
from redprompt.tests_plugins.base import (
    ProbeRecord,
    SecurityTest,
    TargetInfo,
    TestContext,
    TestResult,
    make_probe_record,
)
from redprompt.tests_plugins.markers import OWASP

_AUTH_HEADERS = {"authorization", "x-api-key"}


class _APITest(SecurityTest):
    category = Category.API
    references = [OWASP]

    def _endpoint(self, ctx: TestContext) -> str:
        provider = ctx.provider
        return provider.conn.url(getattr(provider, "default_endpoint", None))

    async def _send(self, ctx: TestContext, *, headers: dict, body: dict) -> Any:
        provider = ctx.provider
        return await provider.client.request(
            "POST", self._endpoint(ctx), headers=headers, json=body
        )

    def _probe(self, label: str, url: str, body: dict, result: Any, detection: DetectionResult) -> ProbeRecord:
        return ProbeRecord(
            label=label,
            request={"method": "POST", "url": url, "headers": {}, "body": body},
            response={
                "status_code": getattr(result, "status_code", None),
                "text": getattr(result, "text", None),
                "latency_ms": getattr(result, "latency_ms", None),
            },
            detection=detection.as_dict(),
        )


class AuthenticationEnforcement(_APITest):
    id = "RP-API-001"
    name = "Authentication enforcement"
    severity = Severity.HIGH
    description = (
        "For targets configured to require auth, sends a request WITHOUT credentials "
        "and flags a finding if the endpoint still accepts it (2xx)."
    )

    def applies_to(self, target: TargetInfo) -> bool:
        return target.auth_method not in ("none", "", None)

    async def execute(self, ctx: TestContext) -> TestResult:
        if ctx.dry_run:
            return self.skipped_result("dry-run: no traffic sent")
        provider = ctx.provider
        spec = provider.build_request(ProviderRequest.from_prompt("healthcheck"))
        headers = {k: v for k, v in spec.headers.items() if k.lower() not in _AUTH_HEADERS}
        try:
            result = await provider.client.request(spec.method, spec.url, headers=headers, json=spec.json_body)
        except Exception as exc:  # noqa: BLE001
            return self.error_result(f"request failed: {exc}")

        detection = expected_status(
            result.status_code,
            expected={401, 403},
            confidence=0.85,
            reason="endpoint accepted an unauthenticated request (expected 401/403)",
        )
        probe = make_probe_record(self.name, spec, result, detection)
        return self.result(detection, probes=[probe])

    def remediation(self) -> str:
        return "Require and verify authentication server-side on every endpoint; reject missing/invalid credentials with 401/403."


class VerboseErrorDisclosure(_APITest):
    id = "RP-API-002"
    name = "Verbose error disclosure"
    severity = Severity.MEDIUM
    description = "Sends a malformed request body and checks whether the error response leaks stack traces/internal paths."

    async def execute(self, ctx: TestContext) -> TestResult:
        if ctx.dry_run:
            return self.skipped_result("dry-run: no traffic sent")
        url = self._endpoint(ctx)
        # Deliberately wrong shape: value where a string is expected.
        malformed = {"message": {"unexpected": ["nested", "object"]}, "__redprompt": "malformed"}
        try:
            result = await self._send(ctx, headers=ctx.provider.base_headers(), body=malformed)
        except Exception as exc:  # noqa: BLE001
            return self.error_result(f"request failed: {exc}")
        detection = detect_error_leakage(result.text or "")
        return self.result(detection, probes=[self._probe(self.name, url, malformed, result, detection)])

    def remediation(self) -> str:
        return "Return generic error messages to clients; log detailed errors server-side only; never expose stack traces."


class InputValidation(_APITest):
    id = "RP-API-003"
    name = "Input validation / unhandled error"
    severity = Severity.LOW
    description = "Sends an oversized/edge-case input and flags an unhandled 5xx as missing input validation."

    async def execute(self, ctx: TestContext) -> TestResult:
        if ctx.dry_run:
            return self.skipped_result("dry-run: no traffic sent")
        url = self._endpoint(ctx)
        oversized = {"message": "A" * 20000}
        try:
            result = await self._send(ctx, headers=ctx.provider.base_headers(), body=oversized)
        except Exception as exc:  # noqa: BLE001
            return self.error_result(f"request failed: {exc}")
        detection = expected_status(
            result.status_code,
            expected={200, 201, 400, 413, 422},  # graceful handling
            confidence=0.5,
            reason="oversized input caused an unhandled server error (5xx)",
        )
        # Only a 5xx is a finding; other unexpected codes are inconclusive, not fails.
        if detection.status.value == "fail" and not (500 <= result.status_code < 600):
            detection = DetectionResult.inconclusive(f"unexpected status {result.status_code}")
        return self.result(detection, probes=[self._probe(self.name, url, {"message": "<20k chars>"}, result, detection)])

    def remediation(self) -> str:
        return "Validate and bound all inputs; enforce request size limits; handle errors gracefully with 4xx codes."
