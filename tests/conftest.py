"""Fixtures for logging tests.

structlog holds global configuration and contextvars persist across a process,
so every test gets a clean slate. We drive the *real* pipeline (not
structlog.testing.capture_logs, which would bypass our redaction processor) by
writing to an in-memory stream and reading it back.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator

import pytest
import structlog

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import clear_context, configure_logging


@pytest.fixture(autouse=True)
def reset_structlog() -> Iterator[None]:
    structlog.reset_defaults()
    clear_context()
    yield
    clear_context()
    structlog.reset_defaults()


@pytest.fixture(scope="session", autouse=True)
def _forbid_real_home_database() -> Iterator[None]:
    """Session-wide guard: no test may OPEN a database under KingSec's
    real default data directory (``Path.home() / ".kingsec"``).

    Phase 4 incident (docs/STATUS.md): a real developer database at
    ``~/.kingsec/kingsec.db`` was found migrated to a schema no test was
    ever supposed to apply to it - the second such incident, after
    Phase 1's unquoted-path defect wrote migrations there too.

    This is the SECOND design of this guard. The first patched
    ``StorageSettings.data_dir``'s ``default_factory`` directly - fail
    loudly whenever the default was even COMPUTED. Run against the full
    suite, that produced 451 failures across 47 files, all false
    positives: pydantic eagerly evaluates every field's default whenever
    ``Settings()``/``StorageSettings()`` is constructed, including tests
    built entirely from in-memory fakes that never touch a database at
    all (e.g. test_session_api.py's ``app()`` fixture, which needs
    ``Settings()`` only for unrelated JWT config). Computing a path
    string is not the hazard; OPENING or MIGRATING a database there is -
    confirmed empirically: constructing ``StorageSettings()`` against a
    controlled tmp HOME creates nothing on disk.

    The real hazard point, also confirmed by reading the code: both
    ``build_sqlite_url()`` (infrastructure/persistence/database.py, the
    app-wiring path) and ``_resolve_database_url()``
    (alembic/env.py, the migration path) call
    ``data_dir.mkdir(parents=True, exist_ok=True)`` on the
    settings-derived fallback - that mkdir is the real side effect this
    guard exists to prevent, not the antecedent Settings() construction.

    This guard therefore patches ``build_sqlite_url`` directly: if the
    settings-derived data_dir resolves to the real home default, it
    raises immediately, before the mkdir or URL construction happens -
    named path in the message, never silently redirected. The explicit
    ``url=`` path into ``create_database_engine()`` (what nearly every
    test already uses - a tmp file or ``sqlite://`` in-memory) is
    completely untouched, since it never calls ``build_sqlite_url`` at
    all.

    Migration-path scope note: ``alembic/env.py`` cannot safely be
    imported in-process to patch the same way - its module bottom
    unconditionally runs ``run_migrations_online()``/``_offline()`` as a
    side effect of import, expecting Alembic's own script-runner context
    to already be configured. Every migration invocation in this
    codebase (the ``kingsec-migrate`` CLI, and every test) already goes
    through it exclusively via subprocess, never in-process - so an
    in-process patch here would never fire anyway. The subprocess path is
    guarded instead at tests/integration/test_alembic_migrations.py's
    ``_run_alembic()``, whose ``database_url`` parameter is now required
    (not optional-defaulting), closing the one such gap found. A
    permanent, non-test-only fix for programmatic migration invocation is
    Part 2's own investigate-and-propose task, tracked separately.
    """
    import kingsec.infrastructure.persistence.database as _database_module

    original_build_sqlite_url = _database_module.build_sqlite_url

    def _guarded_build_sqlite_url(settings: object) -> str:
        from pathlib import Path

        data_dir = settings.storage.data_dir  # type: ignore[attr-defined]
        real_default = Path.home() / ".kingsec"
        if data_dir == real_default:
            raise RuntimeError(
                f"A test tried to OPEN a database under KingSec's REAL default "
                f"data directory ({real_default}) instead of an isolated tmp "
                "path. Set KINGSEC_STORAGE__DATA_DIR (env var or "
                "monkeypatch.setenv) before calling create_database_engine("
                "settings=...), or pass an explicit url= instead (what most "
                "tests already do). This exact gap let a real developer "
                "database get silently migrated twice - see docs/STATUS.md's "
                "Phase 4 incident log."
            )
        return original_build_sqlite_url(settings)  # type: ignore[arg-type]

    _database_module.build_sqlite_url = _guarded_build_sqlite_url  # type: ignore[assignment]
    try:
        yield
    finally:
        _database_module.build_sqlite_url = original_build_sqlite_url


@pytest.fixture
def stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def configure(stream: io.StringIO) -> Callable[..., LoggingSettings]:
    """Configure logging from real LoggingSettings, writing to the test stream."""

    def _configure(*, level: str = "INFO", json_format: bool = False) -> LoggingSettings:
        settings = LoggingSettings(level=level, json_format=json_format)
        configure_logging(settings, stream=stream)
        return settings

    return _configure


@pytest.fixture
def read_json(stream: io.StringIO) -> Callable[[], list[dict]]:
    """Parse the captured stream as one JSON object per line."""

    def _read() -> list[dict]:
        stream.seek(0)
        return [json.loads(line) for line in stream.read().splitlines() if line.strip()]

    return _read
