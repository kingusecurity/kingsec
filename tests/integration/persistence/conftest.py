"""Builders and fixtures shared by persistence integration tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import io

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
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
    create_database_engine,
    create_schema,
    create_session_factory,
)


def utc(day: int = 1) -> datetime:
    return datetime(2026, 1, day, tzinfo=timezone.utc)


def completed_assessment() -> Assessment:
    """A COMPLETED assessment with one enriched, confirmed finding."""

    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", utc(), scope="10.0.0.5"))
    assessment.start()

    finding = Finding.create("SQL Injection", "id param injectable", Severity.CRITICAL)
    finding.add_evidence(Evidence("payload", "' OR 1=1--", utc(2)))
    finding.add_recommendation(
        Recommendation("Parameterize queries", "Use bound params", Severity.CRITICAL)
    )
    finding.confirm()
    assessment.record_finding(finding)

    low = Finding.create("Missing headers", "no CSP", Severity.LOW)
    assessment.record_finding(low)

    assessment.complete()
    return assessment


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
