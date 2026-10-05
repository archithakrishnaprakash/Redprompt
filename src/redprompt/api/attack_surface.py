"""AI application attack-surface graph — pure, no web/DB dependency.

Builds a node/edge graph of a target's attack surface from its declared
capabilities, and annotates each node's status from scan results:

    vulnerable  a finding exists in the node's category
    tested      the node's category was exercised, no finding
    untested    the node exists but its category was not scanned
    discovered  structural/root node

Node → category mapping is explicit so the graph is honest: we never mark a node
"tested" for a category the scan did not cover.
"""

from __future__ import annotations

from typing import Any

# component -> the security category that exercises it
_COMPONENT_CATEGORY = {
    "prompt": "prompt",
    "llm_api": "prompt",
    "rag": "rag",
    "retriever": "rag",
    "documents": "rag",
    "agent": "agent",
    "tools": "agent",
    "file": "file",
    "auth": "api",
    "api": "api",
}


def _status(category: str | None, tested: set[str], vulnerable: set[str]) -> str:
    if category is None:
        return "discovered"
    if category in vulnerable:
        return "vulnerable"
    if category in tested:
        return "tested"
    return "untested"


def build_attack_surface(
    *,
    app_type: str,
    rag_enabled: bool = False,
    agent_enabled: bool = False,
    file_upload: bool = False,
    auth_method: str = "none",
    tools: list[str] | None = None,
    tested_categories: set[str] | None = None,
    vulnerable_categories: set[str] | None = None,
) -> dict[str, Any]:
    tested = tested_categories or set()
    vulnerable = vulnerable_categories or set()
    tools = tools or []

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []

    def add(node_id: str, label: str, component: str | None) -> None:
        category = _COMPONENT_CATEGORY.get(component) if component else None
        nodes.append(
            {
                "id": node_id,
                "label": label,
                "component": component or "root",
                "status": _status(category, tested, vulnerable),
                "category": category,
            }
        )

    def link(a: str, b: str) -> None:
        edges.append({"from": a, "to": b})

    add("app", f"AI Application ({app_type})", None)

    # Prompt interface + LLM API are always present.
    add("prompt", "Prompt interface", "prompt")
    add("llm", "LLM API", "llm_api")
    link("app", "prompt")
    link("prompt", "llm")

    if auth_method not in ("none", "", None):
        add("auth", f"Authentication ({auth_method})", "auth")
        link("app", "auth")

    if rag_enabled:
        add("rag", "RAG pipeline", "rag")
        add("retriever", "Retriever", "retriever")
        add("documents", "Documents", "documents")
        link("app", "rag")
        link("rag", "retriever")
        link("retriever", "documents")

    if agent_enabled:
        add("agent", "Agent", "agent")
        add("tools", f"Tools ({len(tools)})", "tools")
        link("app", "agent")
        link("agent", "tools")
        for i, tool in enumerate(tools):
            tid = f"tool_{i}"
            add(tid, tool, "tools")
            link("tools", tid)

    if file_upload:
        add("file", "File processing", "file")
        link("app", "file")

    counts: dict[str, int] = {}
    for n in nodes:
        counts[n["status"]] = counts.get(n["status"], 0) + 1

    return {"nodes": nodes, "edges": edges, "status_counts": counts}
