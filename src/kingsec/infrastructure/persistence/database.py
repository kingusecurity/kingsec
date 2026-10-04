"""Engine, session factory, schema creation, and connection lifecycle.

This module owns the SQLAlchemy "plumbing": how a database connection is opened,
how sessions are produced, and how the schema is created. Repositories receive a
``sessionmaker`` from here and never construct engines themselves.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

if TYPE_CHECKING:  # import for typing only; no runtime coupling to config internals
    from kingsec.infrastructure.config import Settings

# Default filename for the on-disk SQLite database inside the data directory.
_DATABASE_FILENAME = "kingsec.db"


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
    """Configure per-connection SQLite pragmas.

    * ``foreign_keys=ON`` — SQLite does NOT enforce foreign keys by default,
      which would silently allow orphaned findings/evidence.
    * ``journal_mode=WAL`` — lets readers proceed without blocking on a writer
      (the default rollback-journal mode serializes all access).
    * ``busy_timeout=10000`` — SQLite's default busy timeout is 0ms, so any
      remaining writer-writer contention (e.g. a background scan job saving
      an assessment while a foreground request updates a user) fails
      instantly with "database is locked" instead of waiting briefly.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.close()


def build_sqlite_url(settings: Settings) -> str:
    """Derive the SQLite URL from settings, creating the data directory.

    Args:
        settings: The application settings (uses ``settings.storage.data_dir``).

    Returns:
        A SQLAlchemy SQLite URL pointing at ``<data_dir>/kingsec.db``.
    """
    data_dir: Path = settings.storage.data_dir
    # Defensive: ensure the directory exists even if bootstrap hasn't run.
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{data_dir / _DATABASE_FILENAME}"


def create_database_engine(
    *,
    url: str | None = None,
    settings: Settings | None = None,
    echo: bool = False,
) -> Engine:
    """Create a configured SQLAlchemy engine.

    Exactly one of ``url`` or ``settings`` must be provided. ``url`` is handy for
    tests (e.g. a temp file); ``settings`` is the production path.

    Args:
        url: An explicit SQLAlchemy URL (takes precedence if given).
        settings: Application settings used to derive the SQLite URL.
        echo: If True, log all emitted SQL (debugging only).

    Returns:
        A ready-to-use ``Engine`` with SQLite foreign keys enforced.

    Raises:
        ValueError: If neither ``url`` nor ``settings`` is provided.
    """
    if url is None:
        if settings is None:
            raise ValueError("create_database_engine requires either 'url' or 'settings'")
        url = build_sqlite_url(settings)

    engine = create_engine(
        url,
        echo=echo,
        # SQLite guards against cross-thread use by default; we allow it because
        # a session is never shared across threads concurrently in our design.
        connect_args={"check_same_thread": False},
        future=True,
    )
    # Register the FK pragma for every new connection this engine opens.
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a ``sessionmaker`` bound to the engine.

    ``expire_on_commit=False`` keeps ORM instances usable immediately after a
    commit, which simplifies mapping ORM -> domain right after a write.

    Args:
        engine: The engine sessions will bind to.

    Returns:
        A configured ``sessionmaker``.
    """
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def create_schema(engine: Engine) -> None:
    """Create all tables if they do not already exist.

    .. deprecated::
        Retained for test fixtures and quick-start scenarios only.
        Production deployments MUST use ``alembic upgrade head`` instead.

    Args:
        engine: The engine whose database the schema is created in.
    """
    Base.metadata.create_all(engine)


class SchemaNotMigratedError(RuntimeError):
    """The database has not been migrated via Alembic.

    A dedicated subclass (not a bare ``RuntimeError``) so callers - the
    server's own startup error boundary, in particular - can catch this
    specific, known, actionable condition and print the same remediation
    message ``kingsec-bootstrap`` already uses, instead of either a raw
    traceback or a second, independently-worded message.
    """


def validate_schema_version(engine: Engine) -> None:
    """Verify that the database has been migrated via Alembic.

    Checks for the ``alembic_version`` table and a recorded version. Raises
    ``SchemaNotMigratedError`` if the database appears unmigrated — this
    prevents the application from starting with a stale or empty schema.

    Args:
        engine: The engine connected to the target database.

    Raises:
        SchemaNotMigratedError: If ``alembic_version`` is missing or has no
            version row.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)

    if "alembic_version" not in inspector.get_table_names():
        raise SchemaNotMigratedError("Database schema is not up to date.\nRun:\n  alembic upgrade head")

    with engine.connect() as conn:
        result = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
        row = result.fetchone()

    if row is None:
        raise SchemaNotMigratedError("Database schema is not up to date.\nRun:\n  alembic upgrade head")
