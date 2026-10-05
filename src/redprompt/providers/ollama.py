"""Ollama (local models) adapter — uses the /api/chat endpoint."""

from __future__ import annotations

from typing import Any

from redprompt.providers.base import (
    HTTPRequestSpec,
    ModelProvider,
    ProviderRequest,
)


class OllamaProvider(ModelProvider):
    name = "ollama"
    default_endpoint = "/api/chat"

    def build_request(self, req: ProviderRequest) -> HTTPRequestSpec:
        options: dict[str, Any] = {}
        if req.temperature is not None:
            options["temperature"] = req.temperature
        if req.max_tokens is not None:
            options["num_predict"] = req.max_tokens
        body: dict[str, Any] = {
            "model": self.conn.model or "llama3",
            "messages": [{"role": m.role, "content": m.content} for m in req.messages],
            "stream": req.stream,
        }
        if options:
            body["options"] = options
        body.update(req.extra)
        return HTTPRequestSpec(
            method="POST",
            url=self.conn.url(self.default_endpoint),
            headers=self.base_headers(),
            json_body=body,
        )

    def parse_response(
        self, status_code: int, body: Any, headers: dict[str, str]
    ) -> tuple[str, dict[str, Any]]:
        if not isinstance(body, dict):
            return (str(body), {})
        message = body.get("message") or {}
        text = message.get("content", "") if isinstance(message, dict) else ""
        return text, {
            "model": body.get("model"),
            "finish_reason": body.get("done_reason"),
            "tool_calls": message.get("tool_calls", []) if isinstance(message, dict) else [],
        }
