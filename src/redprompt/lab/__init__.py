"""RedPrompt controlled vulnerable lab.

Intentionally-insecure local AI applications used as reproducible test targets for
RedPrompt. They simulate the *behaviour* of vulnerable LLM/RAG/agent/API apps
deterministically (no real model), so scans produce the same findings every run.

⚠ These apps are INSECURE BY DESIGN. Run them only locally, never expose them to
untrusted networks, and never reuse this code in production. They contain no real
secrets — only clearly-fake lab canaries.
"""

from __future__ import annotations

from redprompt.lab.apps import (
    APP_FACTORIES,
    create_agent_app,
    create_api_app,
    create_chatbot_app,
    create_docagent_app,
    create_rag_app,
)

__all__ = [
    "APP_FACTORIES",
    "create_agent_app",
    "create_api_app",
    "create_chatbot_app",
    "create_docagent_app",
    "create_rag_app",
]
