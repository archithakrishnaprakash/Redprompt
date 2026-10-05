"""Anthropic-compatible Messages API adapter."""

from __future__ import annotations

from typing import Any

from redprompt.providers.base import (
    HTTPRequestSpec,
    ModelProvider,
    ProviderRequest,
    split_system,
)


class AnthropicProvider(ModelProvider):
    name = "anthropic"
    default_endpoint = "/v1/messages"
    anthropic_version = "2023-06-01"

    def build_request(self, req: ProviderRequest) -> HTTPRequestSpec:
        system, rest = split_system(req.messages)
        body: dict[str, Any] = {
            "model": self.conn.model or "claude-3-haiku-20240307",
            "max_tokens": req.max_tokens or 1024,  # required by the API
            "messages": [{"role": m.role, "content": m.content} for m in rest],
        }
        if system:
            body["system"] = system
        if req.temperature is not None:
            body["temperature"] = req.temperature
        body.update(req.extra)

        headers = self.base_headers()
        headers.setdefault("anthropic-version", self.anthropic_version)
        return HTTPRequestSpec(
            method="POST",
            url=self.conn.url(self.default_endpoint),
            headers=headers,
            json_body=body,
        )

    def auth_headers(self) -> dict[str, str]:
        # Anthropic uses the x-api-key header rather than a bearer token.
        if self.conn.auth_method == "none" or not self._credential:
            return {}
        if self.conn.auth_method == "bearer":
            return {"Authorization": f"Bearer {self._credential}"}
        return {"x-api-key": self._credential}

    def parse_response(
        self, status_code: int, body: Any, headers: dict[str, str]
    ) -> tuple[str, dict[str, Any]]:
        if not isinstance(body, dict):
            return (str(body), {})
        blocks = body.get("content") or []
        text_parts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
        tool_calls = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"]
        text = "".join(text_parts) if text_parts else ""
        return text, {
            "model": body.get("model"),
            "finish_reason": body.get("stop_reason"),
            "tool_calls": tool_calls,
        }
