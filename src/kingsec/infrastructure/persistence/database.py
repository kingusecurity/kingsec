"""Engine, session factory, schema creation, and connection lifecycle.

This module owns the SQLAlchemy "plumbing": how a database connection is opened,
how sessions are produced, and how the schema is created. Repositories receive a
``sessionmaker`` from here and never construct engines themselves.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

if TYPE_CHECKING:  # import for typing only; no runtime coupling to config internals
    from kingsec.infrastructure.config import Settings

# Default filename for the on-disk SQLite database inside the data directory.
_DATABASE_FILENAME = "kingsec.db"


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    """Enable foreign-key enforcement for a new SQLite connection.

    SQLite does NOT enforce foreign keys by default, which would silently allow
    orphaned findings/evidence. We turn it on for every connection so our
    ON DELETE CASCADE relationships are actually honoured.
    """

    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def build_sqlite_url(settings: "Settings") -> str:
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
    settings: "Settings | None" = None,
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

    This is the bootstrap-time schema setup. A future module will replace this
    with versioned Alembic migrations; for now ``create_all`` is sufficient and
    idempotent.

    Args:
        engine: The engine whose database the schema is created in.
    """

    Base.metadata.create_all(engine)
