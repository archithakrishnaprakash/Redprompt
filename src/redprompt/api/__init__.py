"""RedPrompt REST API and web dashboard (FastAPI).

The route layer lives in :mod:`redprompt.api.app` and is imported lazily (it needs
the optional ``api`` extra: FastAPI + uvicorn). The pure attack-surface graph
builder in :mod:`redprompt.api.attack_surface` has no web dependency and is used
by both the API and tests.
"""

from __future__ import annotations

from redprompt.api.attack_surface import build_attack_surface

__all__ = ["build_attack_surface"]
