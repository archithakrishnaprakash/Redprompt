"""Shared pytest fixtures for RedPrompt."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from redprompt.config import Settings, load_settings
from redprompt.core.context import AppContext
from redprompt.db.base import create_db_engine, create_session_factory
from redprompt.logging import configure_logging


@pytest.fixture(autouse=True)
def _quiet_logging() -> None:
    configure_logging(level="WARNING", json_logs=False)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Isolated settings backed by a temp SQLite file, ignoring any repo config."""
    db_path = tmp_path / "redprompt-test.db"
    return load_settings(
        search=False,
        overrides={
            "database_url": f"sqlite:///{db_path}",
            "output": {"directory": str(tmp_path / "reports")},
        },
    )


@pytest.fixture
def ctx(settings: Settings) -> Iterator[AppContext]:
    """An AppContext with a freshly-created schema on a temp database."""
    engine = create_db_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    context = AppContext(settings=settings, engine=engine, session_factory=session_factory)
    context.create_schema()
    try:
        yield context
    finally:
        context.dispose()
