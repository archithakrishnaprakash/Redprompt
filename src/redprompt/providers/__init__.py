"""Provider registry and factory.

Credentials are resolved from the environment (by the variable *name* recorded on
the target) at build time and passed to the adapter — they are never stored on the
target record or in the database.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from redprompt.exceptions import ProviderError
from redprompt.http_client import AsyncHTTPClient
from redprompt.providers.anthropic import AnthropicProvider
from redprompt.providers.base import (
    HTTPRequestSpec,
    Message,
    ModelProvider,
    ProviderRequest,
    ProviderResponse,
    TargetConnection,
)
from redprompt.providers.generic import GenericRESTProvider
from redprompt.providers.ollama import OllamaProvider
from redprompt.providers.openai import OpenAIProvider

PROVIDERS: dict[str, type[ModelProvider]] = {
    OpenAIProvider.name: OpenAIProvider,
    AnthropicProvider.name: AnthropicProvider,
    OllamaProvider.name: OllamaProvider,
    GenericRESTProvider.name: GenericRESTProvider,
}


def list_providers() -> list[str]:
    return sorted(PROVIDERS)


def get_provider_class(name: str) -> type[ModelProvider]:
    try:
        return PROVIDERS[name]
    except KeyError as exc:
        raise ProviderError(
            f"unknown provider {name!r}; available: {list_providers()}"
        ) from exc


def build_provider(
    name: str,
    conn: TargetConnection,
    client: AsyncHTTPClient,
    *,
    env: Mapping[str, str] | None = None,
) -> ModelProvider:
    env = os.environ if env is None else env
    credential = env.get(conn.auth_env) if conn.auth_env else None
    provider_cls = get_provider_class(name)
    return provider_cls(conn, client, credential=credential)


__all__ = [
    "PROVIDERS",
    "AnthropicProvider",
    "GenericRESTProvider",
    "HTTPRequestSpec",
    "Message",
    "ModelProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderRequest",
    "ProviderResponse",
    "TargetConnection",
    "build_provider",
    "get_provider_class",
    "list_providers",
]
