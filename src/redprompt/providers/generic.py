"""Generic REST adapter for bespoke AI application endpoints.

Most AI *applications* (as opposed to raw model APIs) expose their own JSON shape,
e.g. ``POST /chat {"message": "..."} -> {"reply": "..."}``. This adapter is driven
by ``TargetConnection.extra`` so it can match those without new code:

    request_field   JSON key to place the prompt under        (default: "message")
    response_path   dotted path to the reply text in the body (default: auto-detect)
    method          HTTP method                                (default: "POST")
    extra_body      static fields merged into every request    (default: {})

If ``response_path`` is not given, common reply keys are tried in order.
"""

from __future__ import annotations

from typing import Any

from redprompt.providers.base import (
    HTTPRequestSpec,
    ModelProvider,
    ProviderRequest,
    dotted_get,
    flatten_messages,
    split_system,
)

_COMMON_REPLY_KEYS = (
    "reply",
    "response",
    "output",
    "text",
    "message",
    "answer",
    "result",
    "completion",
    "content",
)


class GenericRESTProvider(ModelProvider):
    name = "generic"
    default_endpoint = None

    def build_request(self, req: ProviderRequest) -> HTTPRequestSpec:
        _, rest = split_system(req.messages)
        # Prefer the last user turn; fall back to flattened conversation.
        user_turns = [m.content for m in rest if m.role == "user"]
        prompt = user_turns[-1] if user_turns else flatten_messages(req.messages)

        request_field = self.conn.extra.get("request_field", "message")
        body: dict[str, Any] = {request_field: prompt}
        body.update(self.conn.extra.get("extra_body", {}))
        body.update(req.extra)

        method = self.conn.extra.get("method", "POST")
        return HTTPRequestSpec(
            method=method,
            url=self.conn.url(self.default_endpoint),
            headers=self.base_headers(),
            json_body=body,
        )

    def parse_response(
        self, status_code: int, body: Any, headers: dict[str, str]
    ) -> tuple[str, dict[str, Any]]:
        response_path = self.conn.extra.get("response_path")
        if isinstance(body, str):
            return body, {}
        if not isinstance(body, dict):
            return str(body), {}

        if response_path:
            value = dotted_get(body, response_path)
            if value is not None:
                return _as_text(value), {"raw_keys": list(body.keys())}

        for key in _COMMON_REPLY_KEYS:
            if key in body and isinstance(body[key], (str, int, float)):
                return _as_text(body[key]), {"matched_key": key}

        # Nothing matched: surface the whole body so detection still has material.
        return _as_text(body), {"unmatched": True, "raw_keys": list(body.keys())}


def _as_text(value: Any) -> str:
    import json as _json

    if isinstance(value, str):
        return value
    return _json.dumps(value)
