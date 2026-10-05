"""OpenAI-compatible chat-completions adapter.

Works with OpenAI and any compatible server (vLLM, LM Studio, LocalAI, etc.).
"""

from __future__ import annotations

from typing import Any

from redprompt.providers.base import (
    HTTPRequestSpec,
    ModelProvider,
    ProviderRequest,
)


class OpenAIProvider(ModelProvider):
    name = "openai"
    default_endpoint = "/v1/chat/completions"

    def build_request(self, req: ProviderRequest) -> HTTPRequestSpec:
        body: dict[str, Any] = {
            "model": self.conn.model or "gpt-3.5-turbo",
            "messages": [{"role": m.role, "content": m.content} for m in req.messages],
            "stream": req.stream,
        }
        if req.max_tokens is not None:
            body["max_tokens"] = req.max_tokens
        if req.temperature is not None:
            body["temperature"] = req.temperature
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
        choices = body.get("choices") or []
        text = ""
        finish_reason = None
        tool_calls: list[dict[str, Any]] = []
        if choices:
            first = choices[0]
            message = first.get("message") or {}
            text = message.get("content") or ""
            finish_reason = first.get("finish_reason")
            tool_calls = message.get("tool_calls") or []
        return text, {
            "model": body.get("model"),
            "finish_reason": finish_reason,
            "tool_calls": tool_calls,
        }
