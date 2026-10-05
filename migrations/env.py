"""Alembic environment for RedPrompt.

The database URL is resolved from RedPrompt settings (``.redprompt.yml`` /
``REDPROMPT_DATABASE_URL``) rather than hard-coded in ``alembic.ini`` so
migrations always run against the configured store. ``render_as_batch`` is
enabled for SQLite so ALTER operations work under batch mode.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from redprompt.config import load_settings
from redprompt.db.base import Base, create_db_engine

# Import models so their tables are registered on Base.metadata.
from redprompt.db import models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    # Explicit override wins (e.g. `alembic -x db_url=...`); else RedPrompt settings.
    x_args = context.get_x_argument(as_dictionary=True)
    if "db_url" in x_args:
        return x_args["db_url"]
    return load_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_db_engine(_database_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
            poolclass=pool.NullPool,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
