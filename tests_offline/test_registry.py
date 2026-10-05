"""Offline tests for the security-test registry (manual registration)."""

from __future__ import annotations

import unittest

from redprompt.analysis.base import DetectionResult
from redprompt.enums import Category
from redprompt.exceptions import TestPluginError
from redprompt.tests_plugins.base import SecurityTest, TargetInfo, TestContext, TestResult
from redprompt.tests_plugins.registry import TestRegistry


class _PromptTest(SecurityTest):
    id = "RG-PROMPT-1"
    name = "prompt test"
    category = Category.PROMPT

    async def execute(self, ctx: TestContext) -> TestResult:  # pragma: no cover
        return self.result(DetectionResult.passed())


class _AgentTest(SecurityTest):
    id = "RG-AGENT-1"
    name = "agent test"
    category = Category.AGENT

    def applies_to(self, target: TargetInfo) -> bool:
        return target.agent_enabled

    async def execute(self, ctx: TestContext) -> TestResult:  # pragma: no cover
        return self.result(DetectionResult.passed())


class _DupTest(SecurityTest):
    id = "RG-PROMPT-1"  # duplicate id on purpose
    name = "dup"
    category = Category.PROMPT

    async def execute(self, ctx: TestContext) -> TestResult:  # pragma: no cover
        return self.result(DetectionResult.passed())


class _NoIdTest(SecurityTest):
    id = ""  # should be ignored by the registry

    async def execute(self, ctx: TestContext) -> TestResult:  # pragma: no cover
        return self.result(DetectionResult.passed())


def _registry() -> TestRegistry:
    reg = TestRegistry()
    reg.register(_PromptTest)
    reg.register(_AgentTest)
    return reg


class TestRegistryBasics(unittest.TestCase):
    def test_register_and_get(self) -> None:
        reg = _registry()
        self.assertEqual(len(reg), 2)
        self.assertIsInstance(reg.get("RG-PROMPT-1"), _PromptTest)

    def test_unknown_id_raises(self) -> None:
        with self.assertRaises(TestPluginError):
            _registry().get("nope")

    def test_duplicate_id_raises(self) -> None:
        reg = _registry()
        with self.assertRaises(TestPluginError):
            reg.register(_DupTest)

    def test_empty_id_ignored(self) -> None:
        reg = _registry()
        reg.register(_NoIdTest)
        self.assertEqual(len(reg), 2)

    def test_abstract_base_ignored(self) -> None:
        reg = TestRegistry()
        reg.register(SecurityTest)  # abstract -> no-op
        self.assertEqual(len(reg), 0)

    def test_by_category(self) -> None:
        reg = _registry()
        self.assertEqual([t.id for t in reg.by_category(Category.AGENT)], ["RG-AGENT-1"])

    def test_by_category_accepts_str(self) -> None:
        reg = _registry()
        self.assertEqual([t.id for t in reg.by_category("prompt")], ["RG-PROMPT-1"])


class TestPlanning(unittest.TestCase):
    def _target(self, **kw) -> TargetInfo:
        base = dict(name="lab", base_url="http://127.0.0.1:8000", authorized=True)
        base.update(kw)
        return TargetInfo(**base)

    def test_applies_to_filters_agent_test(self) -> None:
        reg = _registry()
        no_agent = reg.for_target(self._target(agent_enabled=False))
        self.assertNotIn("RG-AGENT-1", [t.id for t in no_agent])
        with_agent = reg.for_target(self._target(agent_enabled=True))
        self.assertIn("RG-AGENT-1", [t.id for t in with_agent])

    def test_category_filter(self) -> None:
        reg = _registry()
        selected = reg.for_target(self._target(agent_enabled=True), categories=["prompt"])
        self.assertEqual([t.id for t in selected], ["RG-PROMPT-1"])

    def test_test_id_filter(self) -> None:
        reg = _registry()
        selected = reg.for_target(self._target(agent_enabled=True), test_ids=["RG-AGENT-1"])
        self.assertEqual([t.id for t in selected], ["RG-AGENT-1"])


if __name__ == "__main__":
    unittest.main()
