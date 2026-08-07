from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError
from kingsec.application.ports.repositories import Asset
from kingsec.application.unit_of_work import UnitOfWorkPort
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Authorization,
    Finding,
    ScannerId,
    ScannerResult,
    Severity,
    Target,
    TargetType,
)
from kingsec.domain.report import Report
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyAssessmentRepository,
    SQLAlchemyAssetRepository,
    SQLAlchemyJobRepository,
    SQLAlchemyReportRepository,
    SQLAlchemyScanRepository,
)
from kingsec.infrastructure.persistence.unit_of_work import (
    SQLAlchemyUnitOfWork,
)


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
def uow(session) -> SQLAlchemyUnitOfWork:
    return SQLAlchemyUnitOfWork(session)


def make_assessment() -> Assessment:
    a = Assessment(AssessmentId.generate(), Target("example.com", TargetType.HOSTNAME))
    a.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
    a.start()
    a.record_finding(Finding.create("Vuln", "desc", Severity.MEDIUM))
    a.complete()
    return a


def make_scan_result() -> ScannerResult:
    return ScannerResult(
        scanner_id=ScannerId("nmap"),
        findings=(Finding.create("Port 80", "HTTP", Severity.LOW),),
        raw_output="",
        duration_seconds=1.0,
    )


class TestPortConformance:
    def test_is_unit_of_work_port(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert isinstance(uow, UnitOfWorkPort)

    def test_begin_sets_active(self, uow: SQLAlchemyUnitOfWork) -> None:
        uow.begin()
        assert uow._active is True
        uow.rollback()

    def test_double_begin_raises(self, uow: SQLAlchemyUnitOfWork) -> None:
        uow.begin()
        with pytest.raises(RuntimeError):
            uow.begin()
        uow.rollback()

    def test_commit_without_begin_raises(self, uow: SQLAlchemyUnitOfWork) -> None:
        with pytest.raises(RuntimeError):
            uow.commit()

    def test_rollback_without_begin_is_safe(self, uow: SQLAlchemyUnitOfWork) -> None:
        uow.rollback()

    def test_close_is_idempotent(self, uow: SQLAlchemyUnitOfWork) -> None:
        uow.close()
        uow.close()


class TestRepositories:
    def test_exposes_assessment_repository(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert uow.assessment_repository is not None

    def test_exposes_report_repository(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert uow.report_repository is not None

    def test_exposes_scan_repository(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert uow.scan_repository is not None

    def test_exposes_job_repository(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert uow.job_repository is not None

    def test_exposes_asset_repository(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert uow.asset_repository is not None

    def test_repositories_share_same_session(self, uow: SQLAlchemyUnitOfWork) -> None:
        assert uow.assessment_repository._session is uow.report_repository._session
        assert uow.report_repository._session is uow.scan_repository._session
        assert uow.scan_repository._session is uow.job_repository._session
        assert uow.job_repository._session is uow.asset_repository._session


class TestContextManager:
    def test_context_manager_commits(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                a = make_assessment()
                uow.assessment_repository.save(a)
                uow.commit()

        with Session(engine) as s2:
            repo = SQLAlchemyAssessmentRepository(s2)
            loaded = repo.get(a.id)
            assert loaded.id == a.id

    def test_context_manager_rolls_back_on_exception_before_commit(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            a2 = make_assessment()
            try:
                with uow:
                    uow.assessment_repository.save(a2)
                    msg = "intentional"
                    raise ValueError(msg)
            except ValueError:
                pass

        with Session(engine) as s2:
            repo = SQLAlchemyAssessmentRepository(s2)
            with pytest.raises(AssessmentNotFoundError):
                repo.get(a2.id)

    def test_context_manager_rolls_back_on_exception_after_commit(self, engine) -> None:
        assessment_id = None
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            try:
                with uow:
                    a = make_assessment()
                    assessment_id = a.id
                    uow.assessment_repository.save(a)
                    uow.commit()
                    msg = "intentional"
                    raise ValueError(msg)
            except ValueError:
                pass

        with Session(engine) as s2:
            repo = SQLAlchemyAssessmentRepository(s2)
            loaded = repo.get(assessment_id)
            assert loaded.id == assessment_id

    def test_context_manager_rolls_back_without_commit(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                a = make_assessment()
                uow.assessment_repository.save(a)

        with Session(engine) as s2:
            repo = SQLAlchemyAssessmentRepository(s2)
            with pytest.raises(AssessmentNotFoundError):
                repo.get(a.id)

    def test_context_manager_returns_self(self, uow: SQLAlchemyUnitOfWork) -> None:
        with uow as ctx:
            assert ctx is uow


class TestCrossRepository:
    def test_assessment_and_report_in_same_transaction(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                a = make_assessment()
                uow.assessment_repository.save(a)
                report = Report.from_assessment(a)
                uow.report_repository.save(report)
                uow.commit()

        with Session(engine) as s2:
            assert SQLAlchemyAssessmentRepository(s2).get(a.id).id == a.id
            assert SQLAlchemyReportRepository(s2).get(a.id).assessment_id == str(a.id)

    def test_scan_and_asset_in_same_transaction(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                result = make_scan_result()
                uow.scan_repository.save("scan-1", result)
                asset = Asset(
                    id="asset-uow-1",
                    target=Target("10.0.0.1", TargetType.IP_ADDRESS),
                    discovered_at=datetime.now(UTC),
                )
                uow.asset_repository.add(asset)
                uow.commit()

        with Session(engine) as s2:
            assert SQLAlchemyScanRepository(s2).exists("scan-1") is True
            assert SQLAlchemyAssetRepository(s2).exists("asset-uow-1") is True

    def test_rollback_undoes_all_writes(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                a = make_assessment()
                uow.assessment_repository.save(a)
                result = make_scan_result()
                uow.scan_repository.save("scan-rb", result)
                uow.asset_repository.add(
                    Asset(
                        id="asset-rb",
                        target=Target("10.0.0.2", TargetType.IP_ADDRESS),
                        discovered_at=datetime.now(UTC),
                    )
                )

        with Session(engine) as s2:
            with pytest.raises(AssessmentNotFoundError):
                SQLAlchemyAssessmentRepository(s2).get(a.id)
            assert SQLAlchemyScanRepository(s2).exists("scan-rb") is False
            assert SQLAlchemyAssetRepository(s2).exists("asset-rb") is False

    def test_writes_visible_across_repositories_within_uow(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                a = make_assessment()
                uow.assessment_repository.save(a)
                loaded = uow.assessment_repository.get(a.id)
                assert loaded.id == a.id
                uow.commit()

    def test_multiple_operations_same_repository(self, engine) -> None:
        with Session(engine) as session:
            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                a1 = make_assessment()
                a2 = make_assessment()
                uow.assessment_repository.save(a1)
                uow.assessment_repository.save(a2)
                uow.commit()

        with Session(engine) as s2:
            repo = SQLAlchemyAssessmentRepository(s2)
            assert repo.get(a1.id).id == a1.id
            assert repo.get(a2.id).id == a2.id

    def test_independent_uow_instances_sharing_one_session_dont_interfere(self, engine) -> None:
        """Two separate UnitOfWork wrapper instances built over the same
        underlying Session (not two sessions) must not stomp on each
        other's commits."""
        from kingsec.application.jobs import JobId, JobStatus, ScanJob

        with Session(engine) as session:
            now = datetime.now(UTC)
            uow1 = SQLAlchemyUnitOfWork(session)
            with uow1:
                uow1.job_repository.save(
                    ScanJob(id=JobId("shared-session-1"), target="first.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
                )
                uow1.commit()

            uow2 = SQLAlchemyUnitOfWork(session)
            with uow2:
                uow2.job_repository.save(
                    ScanJob(id=JobId("shared-session-2"), target="second.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
                )
                uow2.commit()

            assert uow2.job_repository.get("shared-session-1").target == "first.com"
            assert uow2.job_repository.get("shared-session-2").target == "second.com"

    def test_rollback_of_pending_write_preserves_prior_commit_in_same_session(self, engine) -> None:
        """Rolling back a later, uncommitted write in a session must not
        erase an earlier write that was already committed in that same
        session."""
        from kingsec.application.jobs import JobId, JobStatus, ScanJob

        with Session(engine) as session:
            now = datetime.now(UTC)
            repo = SQLAlchemyJobRepository(session)
            repo.save(ScanJob(id=JobId("pre-existing"), target="stable.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now))
            session.commit()

            uow = SQLAlchemyUnitOfWork(session)
            with uow:
                uow.job_repository.save(
                    ScanJob(id=JobId("during-error"), target="unstable.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
                )
                uow.rollback()

            assert repo.get("pre-existing").target == "stable.com"
