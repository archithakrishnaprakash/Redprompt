"""Single source of truth for the RedPrompt version."""

from __future__ import annotations

__version__ = "0.1.0"


def get_version() -> str:
    """Return the installed RedPrompt version string."""
    return __version__
