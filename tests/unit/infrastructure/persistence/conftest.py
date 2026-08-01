"""Fixtures for persistence integration tests.

Each test gets a fresh, real SQLite database in a temp file (not in-memory, so
behaviour matches production, including foreign-key cascades). Structured logging
is routed to an in-memory stream so test output stays clean while still
exercising the logging integration.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kingsec.domain import (
    Assessment,
    Authorization,
    Evidence,
    Finding,
    Recommendation,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging
from kingsec.infrastructure.persistence import (
    SQLAlchemyAssessmentRepository,
    SQLAlchemyReportRepository,
    create_database_engine,
    create_schema,
    create_session_factory,
)


def utc() -> datetime:
    """Return a timezone-aware UTC datetime (fixed, for deterministic tests)."""
    return datetime(2026, 1, 1, tzinfo=UTC)


def completed_assessment() -> Assessment:
    """Build a fully completed Assessment with 2 findings for mapper tests.

    Lifecycle: DRAFT -> AUTHORIZED -> RUNNING -> COMPLETED.
    Findings:
        - CRITICAL "SQL Injection" with 1 evidence + 1 recommendation (CONFIRMED)
        - LOW "Missing headers" (OPEN)
    """
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", utc(), scope="10.0.0.5"))
    assessment.start()

    sqli = Finding.create("SQL Injection", "injectable param", Severity.CRITICAL)
    sqli.add_evidence(Evidence("payload", "matched http://10.0.0.5", utc()))
    sqli.add_recommendation(Recommendation("Fix SQLi", "use params", Severity.CRITICAL))
    sqli.confirm()
    assessment.record_finding(sqli)

    assessment.record_finding(Finding.create("Missing headers", "no CSP", Severity.LOW))

    assessment.complete()
    return assessment


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(LoggingSettings(level="INFO", json_format=True), stream=io.StringIO())


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
def assessment_repo(session_factory) -> SQLAlchemyAssessmentRepository:
    return SQLAlchemyAssessmentRepository(session_factory)


@pytest.fixture
def report_repo(session_factory) -> SQLAlchemyReportRepository:
    return SQLAlchemyReportRepository(session_factory)
