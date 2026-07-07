"""Integration tests for the SQLAlchemy Unit of Work (real SQLite)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kingsec.application import (
    AssessmentNotFoundError,
    ReportNotFoundError,
    UnitOfWorkFactory,
)
from kingsec.bootstrap import Container
from kingsec.domain import (
    Assessment,
    AssessmentId,
    AssessmentStatus,
    Authorization,
    Finding,
    Report,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.persistence import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
    SqlAlchemyUnitOfWork,
    SqlAlchemyUnitOfWorkFactory,
    create_database_engine,
    create_session_factory,
    register_unit_of_work,
)
from kingsec.shared.errors import PersistenceError


@pytest.fixture
def uow_factory(session_factory) -> SqlAlchemyUnitOfWorkFactory:
    return SqlAlchemyUnitOfWorkFactory(session_factory)


def _authorized() -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", _now(), scope="10.0.0.5"))
    return assessment


def _now():
    from datetime import datetime, timezone

    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _completed_with_finding() -> Assessment:
    assessment = _authorized()
    assessment.start()
    assessment.record_finding(Finding.create("SQLi", "x", Severity.CRITICAL))
    assessment.complete()
    return assessment


class TestCommitAndRollback:
    def test_commit_persists(self, uow_factory, assessment_repo) -> None:
        assessment = _authorized()
        with uow_factory() as uow:
            uow.assessments.save(assessment)
            uow.commit()

        # Visible to an independent (autocommit) repository afterwards.
        assert assessment_repo.get(assessment.id).is_authorized is True

    def test_missing_commit_rolls_back(self, uow_factory, assessment_repo) -> None:
        assessment = _authorized()
        with uow_factory() as uow:
            uow.assessments.save(assessment)  # no commit -> discarded on exit

        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(assessment.id)

    def test_exception_rolls_back(self, uow_factory, assessment_repo) -> None:
        assessment = _authorized()
        with pytest.raises(RuntimeError):
            with uow_factory() as uow:
                uow.assessments.save(assessment)
                raise RuntimeError("boom before commit")

        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(assessment.id)

    def test_explicit_rollback(self, uow_factory, assessment_repo) -> None:
        assessment = _authorized()
        with uow_factory() as uow:
            uow.assessments.save(assessment)
            uow.rollback()
            uow.commit()  # nothing left to commit after an explicit rollback

        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(assessment.id)


class TestAtomicMultiWrite:
    def test_two_aggregates_commit_together(
        self, uow_factory, assessment_repo, report_repo
    ) -> None:
        assessment = _completed_with_finding()
        report = Report.from_assessment(assessment)

        with uow_factory() as uow:
            uow.assessments.save(assessment)
            uow.reports.save(report)
            uow.commit()

        assert assessment_repo.get(assessment.id).status is AssessmentStatus.COMPLETED
        assert report_repo.get(assessment.id).total_findings == 1

    def test_failure_after_first_write_rolls_back_both(
        self, uow_factory, assessment_repo, report_repo
    ) -> None:
        assessment = _completed_with_finding()
        report = Report.from_assessment(assessment)

        with pytest.raises(RuntimeError):
            with uow_factory() as uow:
                uow.assessments.save(assessment)  # first write
                uow.reports.save(report)          # second write
                raise RuntimeError("crash before commit")

        # Neither the assessment nor the report was persisted — true atomicity.
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(assessment.id)
        with pytest.raises(ReportNotFoundError):
            report_repo.get(assessment.id)


class TestReadModifyWrite:
    def test_load_modify_save_in_one_transaction(
        self, uow_factory, assessment_repo
    ) -> None:
        # Seed an assessment via the autocommit repo.
        assessment = _authorized()
        assessment.start()
        assessment_repo.save(assessment)

        # Load, mutate, and save within a single transaction.
        with uow_factory() as uow:
            loaded = uow.assessments.get(assessment.id)
            loaded.record_finding(Finding.create("XSS", "reflected", Severity.HIGH))
            loaded.complete()
            uow.assessments.save(loaded)
            uow.commit()

        reloaded = assessment_repo.get(assessment.id)
        assert reloaded.status is AssessmentStatus.COMPLETED
        assert len(reloaded.findings) == 1


class TestErrorTranslation:
    def test_persistence_error_on_missing_schema(self, tmp_path: Path) -> None:
        # No schema created -> the first write fails at flush with a SQLAlchemy
        # error that must surface as PersistenceError.
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'empty.db'}")
        factory = SqlAlchemyUnitOfWorkFactory(create_session_factory(engine))
        try:
            with pytest.raises(PersistenceError) as excinfo:
                with factory() as uow:
                    uow.assessments.save(_authorized())
                    uow.commit()
            assert excinfo.value.code == "KS-STORE-001"
        finally:
            engine.dispose()


class TestFactoryAndWiring:
    def test_factory_returns_fresh_instances(self, uow_factory) -> None:
        first = uow_factory()
        second = uow_factory()
        assert first is not second
        assert isinstance(first, SqlAlchemyUnitOfWork)

    def test_register_unit_of_work_binds_factory(self, tmp_path: Path) -> None:
        container = Container()
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")
        from kingsec.infrastructure.persistence import create_schema

        create_schema(engine)
        register_unit_of_work(container, create_session_factory(engine))

        factory = container.resolve(UnitOfWorkFactory)
        assert isinstance(factory, SqlAlchemyUnitOfWorkFactory)

        # The resolved factory produces working Units of Work.
        assessment = _authorized()
        with factory() as uow:
            uow.assessments.save(assessment)
            uow.commit()
        with factory() as uow:
            assert uow.assessments.get(assessment.id).is_authorized is True
        engine.dispose()
