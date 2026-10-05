"""Pydantic schemas for targets and mapping to a provider connection.

These are pure Pydantic (no SQLAlchemy import) so validation is testable anywhere.
``connection_from_target`` accepts any object exposing the Target attributes
(the ORM row, or a simple stand-in in tests).
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator

from redprompt.enums import AppType, AuthMethod
from redprompt.providers.base import TargetConnection

KNOWN_PROVIDERS = ("openai", "anthropic", "ollama", "generic")


class TargetCreate(BaseModel):
    """Input schema for registering a target."""

    name: str = Field(min_length=1, max_length=128)
    base_url: str = Field(min_length=1, max_length=512)
    api_endpoint: str | None = Field(default=None, max_length=512)
    app_type: AppType = AppType.LLM
    provider: str = "generic"  # wire protocol adapter
    model: str | None = None

    auth_method: AuthMethod = AuthMethod.NONE
    auth_env: str | None = None  # env var NAME holding the credential
    auth_header: str = "Authorization"

    rag_enabled: bool = False
    agent_enabled: bool = False
    file_upload: bool = False
    streaming: bool = False

    environment: str = "local"
    tags: list[str] = Field(default_factory=list)
    authorized: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, value: str) -> str:
        if value not in KNOWN_PROVIDERS:
            raise ValueError(f"unknown provider {value!r}; valid: {list(KNOWN_PROVIDERS)}")
        return value

    @field_validator("base_url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not (value.startswith("http://") or value.startswith("https://")):
            raise ValueError("base_url must start with http:// or https://")
        return value.rstrip("/")

    def to_extra(self) -> dict[str, Any]:
        """Assemble the ORM ``extra`` JSON bag (never contains secrets)."""
        extra = dict(self.extra)
        if self.model:
            extra["model"] = self.model
        if self.auth_env:
            extra["auth_env"] = self.auth_env
        if self.auth_header and self.auth_header != "Authorization":
            extra["auth_header"] = self.auth_header
        return extra


class TargetView(BaseModel):
    """Read schema for API/CLI output."""

    id: int
    name: str
    base_url: str
    api_endpoint: str | None
    app_type: AppType
    llm_provider: str | None
    auth_method: AuthMethod
    rag_enabled: bool
    agent_enabled: bool
    file_upload: bool
    streaming: bool
    environment: str
    tags: list[str]
    authorized: bool

    model_config = {"from_attributes": True}


class _TargetLike(Protocol):
    base_url: str
    api_endpoint: str | None
    auth_method: Any
    llm_provider: str | None
    extra: dict[str, Any]


def connection_from_target(target: _TargetLike) -> TargetConnection:
    """Build a :class:`TargetConnection` from a Target row (or stand-in)."""
    extra = dict(getattr(target, "extra", {}) or {})
    auth_method = target.auth_method
    auth_method_str = auth_method.value if hasattr(auth_method, "value") else str(auth_method)
    return TargetConnection(
        base_url=target.base_url,
        endpoint=target.api_endpoint,
        auth_method=auth_method_str,
        auth_env=extra.get("auth_env"),
        auth_header=extra.get("auth_header", "Authorization"),
        model=extra.get("model"),
        extra_headers=extra.get("headers", {}),
        extra=extra,
    )
