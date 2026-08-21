"""Alembic environment configuration for KingSec.

This module bridges Alembic with the existing KingSec infrastructure:

* **Metadata**: imported from ``kingsec.infrastructure.persistence.models.Base``
  so Alembic sees every table the ORM knows about.
* **Database URL**: resolved from ``kingsec.infrastructure.config.Settings``,
  honouring the same ``KINGSEC_STORAGE__DATA_DIR`` (SQLite) or
  ``KINGSEC_STORAGE__DATABASE_URL`` (PostgreSQL) env vars the app uses.
* **Runners**: ``run_migrations_offline`` emits SQL to stdout (for CI/scripting);
  ``run_migrations_online`` connects to the live database.

SQLite vs PostgreSQL
    The engine creation differs slightly (``connect_args`` for SQLite's
    ``check_same_thread``, event listeners for foreign keys).  The caller
    does not need to care — ``_engine_from_settings`` handles the branching.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from alembic import context
from sqlalchemy import Engine, create_engine, event

if TYPE_CHECKING:
    pass

# Alembic Config object — provides access to values in alembic.ini.
config = context.config

# Configure Python logging from alembic.ini's [loggers] section.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("alembic.env")

# ---------------------------------------------------------------------------
# Metadata import — the single source of truth for "what tables exist".
# ---------------------------------------------------------------------------
# We load models.py directly via importlib.util to avoid triggering the
# persistence package's __init__.py, which imports the full application chain.
# Alembic runs standalone and must not need the entire app wired up.
import importlib.util
from pathlib import Path

_models_path = Path(__file__).resolve().parent.parent / "infrastructure" / "persistence" / "models.py"
_spec = importlib.util.spec_from_file_location("kingsec.infrastructure.persistence.models", _models_path)
_models_module = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_models_module)  # type: ignore[union-attr]

metadata = _models_module.Base.metadata


# ---------------------------------------------------------------------------
# Database URL resolution
# ---------------------------------------------------------------------------


def _resolve_database_url() -> str:
    """Build a SQLAlchemy URL from KingSec settings.

    Precedence:
        1. ``ALEMBIC_DATABASE_URL`` env var (explicit override, useful in CI).
        2. ``KINGSEC_STORAGE__DATABASE_URL`` env var (PostgreSQL / external DB).
        3. Derived SQLite path from ``KINGSEC_STORAGE__DATA_DIR``.

    Returns:
        A SQLAlchemy-compatible connection URL.
    """
    # Explicit CI override — highest precedence.
    explicit = os.environ.get("ALEMBIC_DATABASE_URL")
    if explicit:
        return explicit

    # PostgreSQL / external database URL.
    db_url = os.environ.get("KINGSEC_STORAGE__DATABASE_URL")
    if db_url:
        return db_url

    # Default: derive SQLite path from data_dir setting.
    from kingsec.infrastructure.config.loader import load_settings

    settings = load_settings()
    data_dir = settings.storage.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{data_dir / 'kingsec.db'}"


def _engine_from_settings(url: str | None = None) -> Engine:
    """Create an engine suitable for Alembic migrations.

    Alembic runs in its own process, so we cannot share the application's
    engine.  This function creates a throwaway engine with the same
    connection parameters.

    Args:
        url: Optional explicit URL (overrides settings-based resolution).

    Returns:
        A SQLAlchemy ``Engine`` configured for the target database.
    """
    resolved_url = url or _resolve_database_url()

    if resolved_url.startswith("sqlite"):
        engine = create_engine(
            resolved_url,
            # isolation_level=None puts the DBAPI connection in true autocommit,
            # disabling pysqlite's own implicit-BEGIN heuristic (which only
            # fires before INSERT/UPDATE/DELETE/REPLACE, never before DDL —
            # see http://bugs.python.org/issue10740, cited verbatim in
            # alembic's own ddl/sqlite.py::SQLiteImpl.transactional_ddl).
            # Without this, CREATE/DROP INDEX statements commit immediately
            # regardless of any transaction Alembic or SQLAlchemy believe
            # they are inside, so a failure partway through a migration
            # leaves already-applied DDL permanently on disk. Paired with
            # the "begin" listener below, which makes SQLAlchemy's own
            # transaction boundaries real by issuing BEGIN explicitly —
            # SQLite itself fully supports transactional DDL once pysqlite
            # is out of the way. See docs/audits/KINGSEC-PHASE-19-MIGRATION-ATOMICITY-REPORT.md.
            connect_args={"check_same_thread": False, "isolation_level": None},
            future=True,
        )
        # Enable foreign key enforcement for SQLite — matches the app engine.
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        event.listen(engine, "begin", _emit_explicit_begin)
        return engine

    # PostgreSQL or other database — no special connect_args needed.
    return create_engine(resolved_url, future=True)


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
    """Enable foreign-key enforcement for SQLite connections."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _emit_explicit_begin(conn: Any) -> None:
    """Issue a real BEGIN so SQLite's transactional DDL support is actually used.

    With isolation_level=None (set above), pysqlite never opens a transaction
    on its own — SQLAlchemy's "begin" event is the only remaining place a
    transaction boundary gets established, so this makes it real instead of
    relying on pysqlite's DML-only implicit BEGIN.
    """
    conn.exec_driver_sql("BEGIN")


# ---------------------------------------------------------------------------
# Alembic hooks
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting to the database.

    Useful for:
        * Generating SQL scripts for manual execution.
        * CI verification that the migration chain produces valid SQL.
        * ``alembic upgrade --sql`` workflows.
    """
    url = _resolve_database_url()
    context.configure(
        url=url,
        target_metadata=metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect to the database and apply pending migrations.

    This is the normal path for ``alembic upgrade head``.
    """
    connectable = _engine_from_settings()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=metadata,
            compare_type=True,
            process_revision_directives=_skip_empty_autogenerate_revision,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


def _skip_empty_autogenerate_revision(ctx: Any, _rev: Any, directives: list[Any]) -> None:
    """Suppress ``alembic revision --autogenerate`` when it finds no diff.

    Without this, autogenerate always writes a revision file (with empty
    upgrade()/downgrade() bodies) even when the target database's schema
    already matches the ORM metadata exactly — the mechanism behind this
    project's untracked ``*__no_changes.py`` accumulation.
    """
    if getattr(ctx.config.cmd_opts, "autogenerate", False):
        script = directives[0]
        if script.upgrade_ops.is_empty():
            directives[:] = []
            logger.info("no schema changes detected; skipping empty autogenerate revision")


# ---------------------------------------------------------------------------
# Entry point — Alembic calls this at startup.
# ---------------------------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
