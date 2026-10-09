from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, inspect, pool, text

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None

# Alembic creates alembic_version.version_num as VARCHAR(32). Several revision IDs in this project
# are longer than that ("0003_remediations_branch_cleanup_cols" is 36 characters), which SQLite
# happily stores anyway because it does not enforce VARCHAR lengths -- and which Postgres rejects
# with "value too long for type character varying(32)", aborting the upgrade partway through. So the
# migrations passed locally on SQLite and could never complete on the production backend.
_VERSION_NUM_WIDTH = 255


def _widen_version_table(connection) -> None:
    """Ensure alembic_version.version_num can hold this project's revision identifiers.

    Pre-creating the table means Alembic finds it and uses it as-is instead of creating a narrow
    one; widening an existing table covers databases already stamped by an earlier run. Both paths
    preserve any version already recorded.
    """
    if connection.dialect.name != "postgresql":
        return  # SQLite does not enforce VARCHAR length, so there is nothing to fix
    if "alembic_version" in inspect(connection).get_table_names():
        connection.execute(
            text(
                "ALTER TABLE alembic_version "
                f"ALTER COLUMN version_num TYPE VARCHAR({_VERSION_NUM_WIDTH})"
            )
        )
    else:
        connection.execute(
            text(
                "CREATE TABLE alembic_version ("
                f"version_num VARCHAR({_VERSION_NUM_WIDTH}) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
        )
    connection.commit()


def _database_url() -> str:
    return (
        os.getenv("PQC_PRODUCT_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or config.get_main_option("sqlalchemy.url")
        or ""
    )


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _widen_version_table(connection)
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
