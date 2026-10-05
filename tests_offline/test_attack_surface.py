"""Offline tests for the pure attack-surface graph builder."""

from __future__ import annotations

import unittest

from redprompt.api.attack_surface import build_attack_surface


class TestAttackSurface(unittest.TestCase):
    def test_minimal_llm(self) -> None:
        g = build_attack_surface(app_type="llm")
        ids = {n["id"] for n in g["nodes"]}
        self.assertEqual(ids, {"app", "prompt", "llm"})

    def test_full_agent_rag(self) -> None:
        g = build_attack_surface(
            app_type="agent", rag_enabled=True, agent_enabled=True, file_upload=True,
            auth_method="bearer", tools=["search", "email"],
        )
        ids = {n["id"] for n in g["nodes"]}
        for expected in {"rag", "retriever", "documents", "agent", "tools", "auth", "file", "tool_0", "tool_1"}:
            self.assertIn(expected, ids)

    def test_status_vulnerable_and_tested(self) -> None:
        g = build_attack_surface(
            app_type="rag", rag_enabled=True,
            tested_categories={"prompt", "rag"}, vulnerable_categories={"rag"},
        )
        by_id = {n["id"]: n for n in g["nodes"]}
        self.assertEqual(by_id["rag"]["status"], "vulnerable")
        self.assertEqual(by_id["prompt"]["status"], "tested")

    def test_untested_when_not_scanned(self) -> None:
        g = build_attack_surface(app_type="agent", agent_enabled=True)  # no scans
        by_id = {n["id"]: n for n in g["nodes"]}
        self.assertEqual(by_id["agent"]["status"], "untested")

    def test_edges_connect_app(self) -> None:
        g = build_attack_surface(app_type="rag", rag_enabled=True)
        edges = {(e["from"], e["to"]) for e in g["edges"]}
        self.assertIn(("app", "prompt"), edges)
        self.assertIn(("app", "rag"), edges)

    def test_status_counts(self) -> None:
        g = build_attack_surface(app_type="llm", tested_categories={"prompt"})
        self.assertIn("status_counts", g)
        self.assertGreaterEqual(g["status_counts"].get("tested", 0), 1)


if __name__ == "__main__":
    unittest.main()
