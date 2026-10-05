"""Provider abstraction.

RedPrompt talks to a target application over HTTP. Targets speak different wire
protocols (OpenAI-compatible chat completions, Anthropic Messages, Ollama, or a
bespoke REST shape). A :class:`ModelProvider` adapter normalises this: it turns a
protocol-agnostic :class:`ProviderRequest` into an :class:`HTTPRequestSpec`
(``build_request``) and parses the HTTP response back into normalised text plus
metadata (``parse_response``). Both are pure functions, so protocol handling is
unit-tested without any network; :meth:`generate` wires them to the async client.

Credentials are resolved from the environment by the factory and passed in at
construction time — they are never stored on the target record or persisted.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from redprompt.http_client import AsyncHTTPClient


@dataclass
class Message:
    role: str  # system | user | assistant | tool
    content: str


@dataclass
class TargetConnection:
    base_url: str
    endpoint: str | None = None
    auth_method: str = "none"  # none | bearer | api_key | basic
    auth_env: str | None = None  # env var NAME holding the credential
    auth_header: str = "Authorization"
    model: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def url(self, default_endpoint: str | None = None) -> str:
        endpoint = self.endpoint or default_endpoint or ""
        if not endpoint:
            return self.base_url
        return self.base_url.rstrip("/") + "/" + endpoint.lstrip("/")


@dataclass
class ProviderRequest:
    messages: list[Message]
    max_tokens: int | None = None
    temperature: float | None = None
    stream: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_prompt(
        cls, prompt: str, *, system: str | None = None, **kw: Any
    ) -> ProviderRequest:
        messages = [Message("system", system)] if system else []
        messages.append(Message("user", prompt))
        return cls(messages=messages, **kw)


@dataclass
class HTTPRequestSpec:
    method: str
    url: str
    headers: dict[str, str]
    json_body: dict[str, Any]


@dataclass
class ProviderResponse:
    text: str
    raw: Any
    status_code: int
    latency_ms: int
    model: str | None = None
    finish_reason: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    request: HTTPRequestSpec | None = None
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


def split_system(messages: list[Message]) -> tuple[str | None, list[Message]]:
    """Split out the (concatenated) system message from the rest."""
    system_parts = [m.content for m in messages if m.role == "system"]
    rest = [m for m in messages if m.role != "system"]
    system = "\n".join(system_parts) if system_parts else None
    return system, rest


def flatten_messages(messages: list[Message]) -> str:
    """Flatten messages into a single prompt string (for plain-REST targets)."""
    return "\n".join(f"{m.role}: {m.content}" for m in messages)


def dotted_get(data: Any, path: str) -> Any:
    """Fetch a value by dotted path with numeric list indices, e.g. ``a.0.b``."""
    cursor = data
    for part in path.split("."):
        if isinstance(cursor, list):
            try:
                cursor = cursor[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cursor, dict):
            if part not in cursor:
                return None
            cursor = cursor[part]
        else:
            return None
    return cursor


class ModelProvider(ABC):
    """Base class for target protocol adapters."""

    name: str = "base"
    default_endpoint: str | None = None

    def __init__(
        self,
        conn: TargetConnection,
        client: AsyncHTTPClient,
        *,
        credential: str | None = None,
    ) -> None:
        self.conn = conn
        self.client = client
        self._credential = credential

    # -- pure, unit-testable ------------------------------------------------
    @abstractmethod
    def build_request(self, req: ProviderRequest) -> HTTPRequestSpec: ...

    @abstractmethod
    def parse_response(
        self, status_code: int, body: Any, headers: dict[str, str]
    ) -> tuple[str, dict[str, Any]]:
        """Return ``(text, meta)`` where meta may hold model/finish_reason/tool_calls."""

    def auth_headers(self) -> dict[str, str]:
        if self.conn.auth_method == "none" or not self._credential:
            return {}
        if self.conn.auth_method == "bearer":
            return {"Authorization": f"Bearer {self._credential}"}
        if self.conn.auth_method == "api_key":
            return {self.conn.auth_header: self._credential}
        if self.conn.auth_method == "basic":
            return {"Authorization": f"Basic {self._credential}"}
        return {}

    def base_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(self.conn.extra_headers)
        headers.update(self.auth_headers())
        return headers

    # -- networked ----------------------------------------------------------
    async def generate(self, req: ProviderRequest) -> ProviderResponse:
        spec = self.build_request(req)
        result = await self.client.request(
            spec.method, spec.url, headers=spec.headers, json=spec.json_body
        )
        body: Any
        try:
            body = result.json()
        except Exception:  # noqa: BLE001 - non-JSON body is valid to inspect
            body = result.text
        text, meta = self.parse_response(result.status_code, body, result.headers)
        return ProviderResponse(
            text=text,
            raw=body,
            status_code=result.status_code,
            latency_ms=result.latency_ms,
            model=meta.get("model"),
            finish_reason=meta.get("finish_reason"),
            tool_calls=meta.get("tool_calls", []),
            request=spec,
            attempts=result.attempts,
        )

    def metadata(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "url": self.conn.url(self.default_endpoint),
            "model": self.conn.model,
            "auth_method": self.conn.auth_method,
        }
