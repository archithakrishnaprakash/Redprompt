"""RedPrompt exception hierarchy.

A small, explicit hierarchy keeps error handling honest: the CLI can distinguish
a user/config problem (exit non-zero with a clear message) from an internal bug
(surface the traceback), and safety violations are their own type so they can
never be silently swallowed.
"""

from __future__ import annotations


class RedPromptError(Exception):
    """Base class for all RedPrompt errors."""


class ConfigError(RedPromptError):
    """Raised when configuration is missing or invalid."""


class TargetError(RedPromptError):
    """Raised for problems registering, resolving, or reaching a target."""


class SafetyViolation(RedPromptError):
    """Raised when an action would violate an engagement safety control.

    Examples: scanning an unauthorized/public target, exceeding request limits.
    This is intentionally distinct so it is never caught by broad handlers.
    """


class ProviderError(RedPromptError):
    """Raised when a model/provider adapter fails."""


class TestPluginError(RedPromptError):
    """Raised when a security-test plugin fails to load or execute."""


class EvidenceError(RedPromptError):
    """Raised for evidence collection / persistence problems."""


class ReportError(RedPromptError):
    """Raised when report generation fails."""
