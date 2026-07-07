"""Repository integration tests against a real SQLite database."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kingsec.application import AssessmentNotFoundError, ReportNotFoundError
from kingsec.domain import (
    Assessment,
    AssessmentId,
    AssessmentStatus,
    Authorization,
    Finding,
    FindingStatus,
    Report,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.persistence import (
    SqlAlchemyAssessmentRepository,
    create_database_engine,
    create_session_factory,
)
from kingsec.shared.errors import PersistenceError


def _utc(day: int = 1) -> datetime:
    return datetime(2026, 1, day, tzinfo=timezone.utc)


def _running(repo: SqlAlchemyAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", _utc(), scope="10.0.0.5"))
    assessment.start()
    return assessment


class TestAssessmentPersistence:
    def test_save_and_get_round_trip(self, assessment_repo) -> None:
        assessment = _running(assessment_repo)
        f = Finding.create("SQLi", "injectable", Severity.CRITICAL)
        f.confirm()
        assessment.record_finding(f)
        assessment.complete()
        assessment_repo.save(assessment)

        loaded = assessment_repo.get(assessment.id)
        assert loaded.status is AssessmentStatus.COMPLETED
        assert loaded.findings[0].status is FindingStatus.CONFIRMED
        assert loaded.highest_severity is Severity.CRITICAL

    def test_get_unknown_raises_not_found(self, assessment_repo) -> None:
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(AssessmentId("asmt-missing"))

    def test_update_replaces_state(self, assessment_repo) -> None:
        # Save while RUNNING with one finding...
        assessment = _running(assessment_repo)
        assessment.record_finding(Finding.create("A", "d", Severity.LOW))
        assessment_repo.save(assessment)

        # ...then add another finding, complete, and re-save (delete+insert path).
        assessment.record_finding(Finding.create("B", "d", Severity.HIGH))
        assessment.complete()
        assessment_repo.save(assessment)

        loaded = assessment_repo.get(assessment.id)
        assert loaded.status is AssessmentStatus.COMPLETED
        assert len(loaded.findings) == 2

    def test_failed_assessment_round_trip(self, assessment_repo) -> None:
        assessment = _running(assessment_repo)
        assessment.fail("scanner crashed")
        assessment_repo.save(assessment)

        loaded = assessment_repo.get(assessment.id)
        assert loaded.status is AssessmentStatus.FAILED
        assert loaded.failure_reason == "scanner crashed"


class TestForeignKeyCascade:
    def test_deleting_assessment_removes_findings(self, assessment_repo, session_factory) -> None:
        from kingsec.infrastructure.persistence.models import AssessmentORM, FindingORM

        assessment = _running(assessment_repo)
        assessment.record_finding(Finding.create("A", "d", Severity.LOW))
        assessment.complete()
        assessment_repo.save(assessment)

        # Delete the aggregate directly; ON DELETE CASCADE must remove children.
        with session_factory.begin() as session:
            session.delete(session.get(AssessmentORM, str(assessment.id)))

        with session_factory() as session:
            assert session.query(FindingORM).count() == 0


class TestReportPersistence:
    def test_save_and_get_round_trip(self, assessment_repo, report_repo) -> None:
        assessment = _running(assessment_repo)
        assessment.record_finding(Finding.create("SQLi", "x", Severity.CRITICAL))
        assessment.complete()
        assessment_repo.save(assessment)

        report = Report.from_assessment(assessment)
        report_repo.save(report)

        loaded = report_repo.get(assessment.id)
        assert loaded.verdict.highest_severity is Severity.CRITICAL
        assert loaded.total_findings == 1

    def test_save_is_idempotent_upsert(self, assessment_repo, report_repo) -> None:
        assessment = _running(assessment_repo)
        assessment.complete()
        assessment_repo.save(assessment)
        report = Report.from_assessment(assessment)

        report_repo.save(report)
        report_repo.save(report)  # second save must not raise (merge upsert)

        assert report_repo.get(assessment.id).assessment_id == str(assessment.id)

    def test_get_unknown_raises_not_found(self, report_repo) -> None:
        with pytest.raises(ReportNotFoundError):
            report_repo.get(AssessmentId("asmt-missing"))


class TestExceptionTranslation:
    def test_sqlalchemy_error_becomes_persistence_error(self, tmp_path) -> None:
        # Engine with NO schema created -> querying a missing table raises an
        # OperationalError, which the repository must translate to PersistenceError.
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'empty.db'}")
        repo = SqlAlchemyAssessmentRepository(create_session_factory(engine))
        try:
            with pytest.raises(PersistenceError) as excinfo:
                repo.get(AssessmentId("asmt-1"))
            # The original SQLAlchemy error is preserved as the cause.
            assert excinfo.value.__cause__ is not None
            assert excinfo.value.code == "KS-STORE-001"
        finally:
            engine.dispose()
