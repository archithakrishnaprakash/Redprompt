"""Target CRUD service (SQLAlchemy) and provider/client construction."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from redprompt.config import Settings
from redprompt.db.models import Target
from redprompt.exceptions import TargetError
from redprompt.http_client import AsyncHTTPClient
from redprompt.providers import ModelProvider, build_provider
from redprompt.targets.schemas import TargetCreate, connection_from_target


class TargetService:
    """Create/read/delete targets. Business rules live here, not in the CLI."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, create: TargetCreate) -> Target:
        if self.session.scalar(select(Target).where(Target.name == create.name)):
            raise TargetError(f"a target named {create.name!r} already exists")
        target = Target(
            name=create.name,
            base_url=create.base_url,
            api_endpoint=create.api_endpoint,
            app_type=create.app_type,
            auth_method=create.auth_method,
            llm_provider=create.provider,
            rag_enabled=create.rag_enabled,
            agent_enabled=create.agent_enabled,
            file_upload=create.file_upload,
            streaming=create.streaming,
            environment=create.environment,
            tags=create.tags,
            authorized=create.authorized,
            extra=create.to_extra(),
        )
        self.session.add(target)
        self.session.flush()
        return target

    def get(self, identifier: str | int) -> Target:
        target = self._find(identifier)
        if target is None:
            raise TargetError(f"no such target: {identifier!r}")
        return target

    def _find(self, identifier: str | int) -> Target | None:
        if isinstance(identifier, int) or str(identifier).isdigit():
            found = self.session.get(Target, int(identifier))
            if found:
                return found
        return self.session.scalar(select(Target).where(Target.name == str(identifier)))

    def list(self) -> list[Target]:
        return list(self.session.scalars(select(Target).order_by(Target.name)))

    def remove(self, identifier: str | int) -> None:
        target = self.get(identifier)
        self.session.delete(target)

    def set_authorized(self, identifier: str | int, authorized: bool) -> Target:
        target = self.get(identifier)
        target.authorized = authorized
        return target


def make_client(
    settings: Settings,
    *,
    transport: object | None = None,
    inspector: object | None = None,
) -> AsyncHTTPClient:
    """Build an :class:`AsyncHTTPClient` from scan settings."""
    scan = settings.scan
    return AsyncHTTPClient(
        timeout=settings.target.timeout_seconds,
        connect_timeout=settings.target.connect_timeout_seconds,
        retry_attempts=scan.retry.attempts,
        backoff_seconds=scan.retry.backoff_seconds,
        rate_limit_per_second=scan.rate_limit_per_second,
        max_requests=scan.max_requests_per_target,
        transport=transport,  # type: ignore[arg-type]
        inspector=inspector,
    )


def provider_for_target(
    target: Target,
    client: AsyncHTTPClient,
    *,
    env: dict[str, str] | None = None,
) -> ModelProvider:
    """Construct the provider adapter for a target (credentials from env)."""
    conn = connection_from_target(target)
    provider_name = target.llm_provider or "generic"
    return build_provider(provider_name, conn, client, env=env)


__all__ = ["TargetService", "make_client", "provider_for_target"]
