"""Fixtures for persistence integration tests.

Each test gets a fresh, real SQLite database in a temp file (not in-memory, so
behaviour matches production, including foreign-key cascades). Structured logging
is routed to an in-memory stream so test output stays clean while still
exercising the logging integration.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging
from kingsec.infrastructure.persistence import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
    create_database_engine,
    create_schema,
    create_session_factory,
)


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(
        LoggingSettings(level="INFO", json_format=True), stream=io.StringIO()
    )


@pytest.fixture
def engine(tmp_path: Path):
    eng = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
    create_schema(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session_factory(engine):
    return create_session_factory(engine)


@pytest.fixture
def assessment_repo(session_factory) -> SqlAlchemyAssessmentRepository:
    return SqlAlchemyAssessmentRepository(session_factory)


@pytest.fixture
def report_repo(session_factory) -> SqlAlchemyReportRepository:
    return SqlAlchemyReportRepository(session_factory)
