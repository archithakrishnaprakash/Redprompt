"""RedPrompt: AI Application Security Testing & Red Teaming Platform.

An extensible framework for the *authorized*, controlled security assessment of
LLM, RAG, and agentic applications. RedPrompt is designed for testing systems you
own or are explicitly permitted to test, and ships with a local, intentionally
vulnerable lab so its capabilities can be demonstrated reproducibly without
targeting any third-party system.
"""

from __future__ import annotations

from redprompt.version import __version__, get_version

__all__ = ["__version__", "get_version"]
