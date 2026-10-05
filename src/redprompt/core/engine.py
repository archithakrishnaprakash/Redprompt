"""Scan engine — runs a plan of tests against a target's provider.

Deliberately free of any database or ORM dependency: given a ``TargetInfo``, a
provider, and a list of tests, it enforces scope/safety, executes tests under a
concurrency limit (sharing one request-budgeted client), and returns structured
results. This makes the core execution path fully testable with an ``httpx``
``MockTransport`` and a fake test — no network, no database.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from redprompt.config import Settings
from redprompt.enums import TestStatus
from redprompt.providers.base import ModelProvider
from redprompt.safety import SafetyDecision, evaluate_target
from redprompt.exceptions import SafetyViolation
from redprompt.tests_plugins.base import SecurityTest, TargetInfo, TestContext, TestResult


@dataclass
class ScanEngineResult:
    results: list[TestResult]
    safety: SafetyDecision
    dry_run: bool
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def findings(self) -> list[TestResult]:
        return [r for r in self.results if r.status is TestStatus.FAIL]


def tally(results: list[TestResult]) -> dict[str, int]:
    counts = {s.value: 0 for s in TestStatus}
    for r in results:
        counts[r.status.value] += 1
    counts["total"] = len(results)
    return counts


class ScanEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate_safety(self, target: TargetInfo) -> SafetyDecision:
        s = self.settings.safety
        return evaluate_target(
            target.base_url,
            authorized=target.authorized,
            require_authorization=s.require_authorization,
            block_public_targets=s.block_public_targets,
            allowed_hosts=s.allowed_hosts,
        )

    async def run(
        self,
        target: TargetInfo,
        provider: ModelProvider,
        tests: list[SecurityTest],
        *,
        dry_run: bool = False,
        workers: int | None = None,
        enforce_safety: bool = True,
        logger: object = None,
    ) -> ScanEngineResult:
        decision = self.evaluate_safety(target)
        if enforce_safety and not dry_run and not decision.allowed:
            raise SafetyViolation("; ".join(decision.reasons))

        limit = workers or self.settings.scan.workers
        semaphore = asyncio.Semaphore(max(1, limit))

        async def run_one(test: SecurityTest) -> TestResult:
            if not test.applies_to(target):
                return test.skipped_result("test not applicable to this target")
            if dry_run:
                return test.skipped_result("dry-run: no traffic sent")
            ctx = TestContext(
                target=target, provider=provider, settings=self.settings,
                dry_run=False, logger=logger,
            )
            async with semaphore:
                start = time.monotonic()
                try:
                    result = await test.execute(ctx)
                except SafetyViolation:
                    raise  # budget/scope breaches must surface, never be swallowed
                except Exception as exc:  # noqa: BLE001 - a broken test is ERROR, not FAIL
                    result = test.error_result(f"test raised: {exc}")
                result.duration_ms = int((time.monotonic() - start) * 1000)
                return result

        results = await asyncio.gather(*(run_one(t) for t in tests))
        return ScanEngineResult(
            results=list(results), safety=decision, dry_run=dry_run, counts=tally(list(results))
        )
