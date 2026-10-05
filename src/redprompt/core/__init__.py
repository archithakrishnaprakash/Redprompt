"""RedPrompt core: application context, scan engine, and orchestration.

Submodules are imported directly (e.g. ``from redprompt.core.engine import
ScanEngine``) rather than re-exported here, so importing the pure engine does not
drag in the database-backed context/orchestrator. This keeps the engine testable
without SQLAlchemy installed.
"""

from __future__ import annotations
