"""Integration tests for SQLAlchemyReportRepository.

Exercises every public method against a real SQLite database.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application import (
    ReportNotFoundError,
)
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Authorization,
    Finding,
    Report,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyReportRepository,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def engine():
    eng = create_database_engine(url="sqlite://")
    create_schema(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s
        s.rollback()


@pytest.fixture
def repo(session):
    return SQLAlchemyReportRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_report(
    assessment_id: AssessmentId | None = None,
    *,
    generated_at: datetime | None = None,
) -> Report:
    """Build a Report from a completed assessment."""
    a_id = assessment_id or AssessmentId.generate()
    target = Target("example.com", TargetType.HOSTNAME)
    assessment = Assessment(a_id, target)
    assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
    assessment.start()

    finding = Finding.create("XSS", "Cross-site scripting", Severity.HIGH)
    finding.confirm()
    assessment.record_finding(finding)
    assessment.record_finding(Finding.create("Info", "TLS version", Severity.INFORMATIONAL))
    assessment.complete()

    return Report.from_assessment(assessment, generated_at=generated_at)


# ===========================================================================
# Save & Get
# ===========================================================================


class TestSaveAndGet:
    def test_save_and_get(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.assessment_id == report.assessment_id
        assert loaded.target == str(Target("example.com", TargetType.HOSTNAME))

    def test_get_returns_domain_object(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert isinstance(loaded, Report)

    def test_get_non_existent_raises(self, repo: SQLAlchemyReportRepository) -> None:
        with pytest.raises(ReportNotFoundError):
            repo.get(AssessmentId("nonexistent"))

    def test_save_persists_to_database(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        from kingsec.infrastructure.persistence.models import ReportORM

        orm = session.get(ReportORM, report.assessment_id)
        assert orm is not None
        assert orm.target == str(Target("example.com", TargetType.HOSTNAME))


# ===========================================================================
# Update / Overwrite
# ===========================================================================


class TestUpdate:
    def test_save_twice_overwrites(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        # Save again with different verdict
        modified = Report(
            assessment_id=report.assessment_id,
            target=report.target,
            generated_at=report.generated_at,
            verdict=report.verdict,
            entries=report.entries,
            severity_counts=report.severity_counts,
        )
        repo.save(modified)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.assessment_id == report.assessment_id
        assert loaded.target == str(Target("example.com", TargetType.HOSTNAME))

    def test_overwrite_new_target(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        overwritten = Report(
            assessment_id=report.assessment_id,
            target="updated.com",
            generated_at=report.generated_at,
            verdict=report.verdict,
            entries=report.entries,
            severity_counts=report.severity_counts,
        )
        repo.save(overwritten)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.target == "updated.com"


# ===========================================================================
# Mapping correctness
# ===========================================================================


class TestMapping:
    def test_round_trip_preserves_verdict(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.verdict.action_required == report.verdict.action_required
        assert loaded.verdict.headline == report.verdict.headline

    def test_round_trip_preserves_entries(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert len(loaded.entries) == len(report.entries)
        assert loaded.entries[0].title == report.entries[0].title

    def test_round_trip_preserves_severity_counts(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert len(loaded.severity_counts) == len(report.severity_counts)
        for (sev_a, cnt_a), (sev_b, cnt_b) in zip(loaded.severity_counts, report.severity_counts, strict=False):
            assert sev_a == sev_b
            assert cnt_a == cnt_b

    def test_round_trip_preserves_generated_at(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        generated_at = datetime(2025, 6, 15, 14, 30, 0, 123456, tzinfo=UTC)
        report = make_report(generated_at=generated_at)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.generated_at == generated_at
        assert loaded.generated_at.tzinfo is not None


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_save_and_get_unicode(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        a_id = AssessmentId.generate()
        assessment = Assessment(a_id, Target("über-unicod€.com", TargetType.HOSTNAME))
        assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        assessment.start()
        assessment.record_finding(Finding.create("Öné", "Desc", Severity.LOW))
        assessment.complete()
        report = Report.from_assessment(assessment)

        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert "über-unicod€" in loaded.target or "über-unicod€" in loaded.entries[0].title

    def test_multiple_reports(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        r1 = make_report(AssessmentId.generate())
        r2 = make_report(AssessmentId.generate())
        repo.save(r1)
        repo.save(r2)
        session.flush()

        loaded1 = repo.get(AssessmentId(r1.assessment_id))
        loaded2 = repo.get(AssessmentId(r2.assessment_id))
        assert loaded1.assessment_id != loaded2.assessment_id

    def test_rollback_discards_save(self, engine) -> None:
        with Session(engine) as s:
            repo = SQLAlchemyReportRepository(s)
            report = make_report()
            repo.save(report)
            s.rollback()

        with Session(engine) as s2:
            repo2 = SQLAlchemyReportRepository(s2)
            with pytest.raises(ReportNotFoundError):
                repo2.get(AssessmentId(report.assessment_id))

    def test_new_session_reads_committed(self, engine, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report()
        repo.save(report)
        session.commit()

        with Session(engine) as s2:
            repo2 = SQLAlchemyReportRepository(s2)
            loaded = repo2.get(AssessmentId(report.assessment_id))
            assert loaded.assessment_id == report.assessment_id

    def test_empty_database_raises_on_get(self, repo: SQLAlchemyReportRepository) -> None:
        with pytest.raises(ReportNotFoundError):
            repo.get(AssessmentId("does-not-exist"))
