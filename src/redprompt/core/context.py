"""Application context.

``AppContext`` is the single object that carries resolved configuration, a
configured logger, and database access. Commands and the API receive it via
dependency injection rather than reaching for globals, which keeps the code
testable (tests build a context against an in-memory SQLite database) and makes
the data-flow explicit.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from redprompt.config import Settings, load_settings
from redprompt.db.base import (
    create_all,
    create_db_engine,
    create_session_factory,
    session_scope,
)
from redprompt.logging import configure_logging, get_logger


@dataclass
class AppContext:
    """Runtime services shared across RedPrompt subsystems."""

    settings: Settings
    engine: Engine
    session_factory: sessionmaker[Session]

    @property
    def log(self) -> Any:
        return get_logger("redprompt")

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Open a transactional session scope."""
        with session_scope(self.session_factory) as session:
            yield session

    def create_schema(self) -> None:
        """Create all tables directly (quick-start / tests; prod uses Alembic)."""
        create_all(self.engine)

    def dispose(self) -> None:
        self.engine.dispose()


def build_context(
    config_path: str | Path | None = None,
    *,
    overrides: dict[str, Any] | None = None,
    create_schema: bool = False,
    echo_sql: bool = False,
) -> AppContext:
    """Construct an :class:`AppContext` from configuration.

    Args:
        config_path: explicit ``.redprompt.yml`` path (else discovered/defaults).
        overrides: highest-precedence config overrides (CLI flags map here).
        create_schema: if True, ensure tables exist (handy for SQLite quick-start).
        echo_sql: echo SQL for debugging.
    """
    settings = load_settings(config_path, overrides=overrides)
    configure_logging(level=settings.logging.level, json_logs=settings.logging.json_logs)

    engine = create_db_engine(settings.database_url, echo=echo_sql)
    session_factory = create_session_factory(engine)
    ctx = AppContext(settings=settings, engine=engine, session_factory=session_factory)

    if create_schema:
        ctx.create_schema()
    return ctx
