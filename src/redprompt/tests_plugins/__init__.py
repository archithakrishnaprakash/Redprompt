"""Security-test plugin framework.

Tests are self-contained plugins implementing :class:`SecurityTest`. They are
discovered from this package (and any additional configured packages) by the
:mod:`registry`, planned by category/target applicability, and executed by the
scan engine. This mirrors the extensible layout in the spec:

    tests_plugins/
        base.py registry.py
        prompt/ data/ rag/ agent/ api/   (populated in Phase 4)
"""

from __future__ import annotations

from redprompt.tests_plugins.base import (
    ProbeRecord,
    SecurityTest,
    SingleProbeTest,
    TargetInfo,
    TestContext,
    TestResult,
)

__all__ = [
    "ProbeRecord",
    "SecurityTest",
    "SingleProbeTest",
    "TargetInfo",
    "TestContext",
    "TestResult",
]
