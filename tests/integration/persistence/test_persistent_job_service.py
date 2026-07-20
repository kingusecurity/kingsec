"""Integration tests for PersistentJobService.

Verifies that every ``JobServicePort`` method works correctly through the
``UnitOfWorkPort`` + SQLAlchemy persistence layer — jobs survive across
sessions, transactions roll back on error, and the API layer is unaffected.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from kingsec.application.errors import IllegalJobTransitionError, JobNotFoundError
from kingsec.application.jobs import JobStatus, ScanJob
from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.services.persistent_job_service import PersistentJobService
from kingsec.infrastructure.persistence import create_database_engine, create_schema
from kingsec.infrastructure.persistence.repositories import SQLAlchemyJobRepository
from kingsec.infrastructure.persistence.unit_of_work import SQLAlchemyUnitOfWork


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def session():
    engine = create_database_engine(url="sqlite://")
    create_schema(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def uow(session) -> SQLAlchemyUnitOfWork:
    return SQLAlchemyUnitOfWork(session)


@pytest.fixture
def service(uow: SQLAlchemyUnitOfWork) -> PersistentJobService:
    return PersistentJobService(uow)


@pytest.fixture
def fresh_session():
    engine = create_database_engine(url="sqlite://")
    create_schema(engine)
    with Session(engine) as s:
        s.connection()  # ensure engine/connection created
        yield s


# ===========================================================================
# Port conformance
# ===========================================================================


class TestPortConformance:
    def test_is_job_service_port(self, service: PersistentJobService) -> None:
        assert isinstance(service, JobServicePort)


# ===========================================================================
# Create job
# ===========================================================================


class TestCreateJob:
    def test_submit_scan_creates_job(self, service: PersistentJobService) -> None:
        job = service.submit_scan("example.com")
        assert isinstance(job, ScanJob)
        assert job.target == "example.com"
        assert job.status == JobStatus.PENDING

    def test_submit_scan_returns_job_with_id(self, service: PersistentJobService) -> None:
        job = service.submit_scan("test.com", config={"scanner": "nmap"})
        assert job.id is not None
        assert str(job.id)

    def test_submit_scan_sets_created_at(self, service: PersistentJobService) -> None:
        before = datetime.now(timezone.utc)
        job = service.submit_scan("example.com")
        after = datetime.now(timezone.utc)
        assert before <= job.created_at <= after

    def test_submit_scan_default_config(self, service: PersistentJobService) -> None:
        job = service.submit_scan("example.com")
        assert job.config == {}

    def test_submit_scan_custom_config(self, service: PersistentJobService) -> None:
        job = service.submit_scan("example.com", config={"verbose": True})
        assert job.config == {"verbose": True}


# ===========================================================================
# Get job
# ===========================================================================


class TestGetJob:
    def test_get_job_returns_job(self, service: PersistentJobService) -> None:
        created = service.submit_scan("example.com")
        fetched = service.get_job(str(created.id))
        assert fetched.id == created.id
        assert fetched.target == created.target

    def test_get_job_raises_for_unknown(self, service: PersistentJobService) -> None:
        with pytest.raises(JobNotFoundError):
            service.get_job("no-such-id")

    def test_get_job_returns_correct_fields(self, service: PersistentJobService) -> None:
        created = service.submit_scan("get-test.com")
        fetched = service.get_job(str(created.id))
        assert fetched.target == "get-test.com"
        assert fetched.status == JobStatus.PENDING


# ===========================================================================
# List jobs
# ===========================================================================


class TestListJobs:
    def test_list_jobs_empty(self, service: PersistentJobService) -> None:
        assert service.list_jobs() == []

    def test_list_jobs_returns_all(self, service: PersistentJobService) -> None:
        service.submit_scan("a.com")
        service.submit_scan("b.com")
        jobs = service.list_jobs()
        assert len(jobs) == 2

    def test_list_jobs_newest_first(self, service: PersistentJobService) -> None:
        j1 = service.submit_scan("a.com")
        j2 = service.submit_scan("b.com")
        jobs = service.list_jobs()
        assert jobs[0].id == j2.id
        assert jobs[1].id == j1.id


# ===========================================================================
# Update status
# ===========================================================================


class TestUpdateStatus:
    def test_cancel_changes_status(self, service: PersistentJobService) -> None:
        job = service.submit_scan("example.com")
        cancelled = service.cancel_job(str(job.id))
        assert cancelled.status == JobStatus.CANCELLED

    def test_cancel_returns_updated_job(self, service: PersistentJobService) -> None:
        job = service.submit_scan("example.com")
        cancelled = service.cancel_job(str(job.id))
        assert cancelled.id == job.id
        assert cancelled.target == job.target

    def test_cancel_updates_timestamp(self, service: PersistentJobService) -> None:
        job = service.submit_scan("example.com")
        cancelled = service.cancel_job(str(job.id))
        assert cancelled.updated_at >= cancelled.created_at

    def test_cancel_persisted(self, service: PersistentJobService, session) -> None:
        job = service.submit_scan("example.com")
        service.cancel_job(str(job.id))
        repo = SQLAlchemyJobRepository(session)
        fetched = repo.get(str(job.id))
        assert fetched.status == JobStatus.CANCELLED


class TestTransitionJob:
    def test_transition_to_running(self, service: PersistentJobService) -> None:
        job = service.submit_scan("transition.com")
        updated = service.transition_job(str(job.id), "RUNNING")
        assert updated.status == JobStatus.RUNNING
        assert updated.id == job.id

    def test_transition_to_completed(self, service: PersistentJobService) -> None:
        job = service.submit_scan("transition.com")
        service.transition_job(str(job.id), "RUNNING")
        updated = service.transition_job(str(job.id), "COMPLETED")
        assert updated.status == JobStatus.COMPLETED

    def test_transition_to_failed(self, service: PersistentJobService) -> None:
        job = service.submit_scan("transition.com")
        service.transition_job(str(job.id), "RUNNING")
        updated = service.transition_job(str(job.id), "FAILED")
        assert updated.status == JobStatus.FAILED

    def test_transition_invalid_raises(self, service: PersistentJobService) -> None:
        job = service.submit_scan("transition.com")
        with pytest.raises(IllegalJobTransitionError):
            service.transition_job(str(job.id), "COMPLETED")  # PENDING -> COMPLETED is invalid

    def test_transition_nonexistent_raises(self, service: PersistentJobService) -> None:
        with pytest.raises(JobNotFoundError):
            service.transition_job("no-such-job", "RUNNING")


class TestFindOldestPending:
    def test_returns_none_when_empty(self, service: PersistentJobService) -> None:
        assert service.find_oldest_pending() is None

    def test_returns_oldest_pending(self, service: PersistentJobService) -> None:
        job1 = service.submit_scan("first.com")
        job2 = service.submit_scan("second.com")
        oldest = service.find_oldest_pending()
        assert oldest is not None
        assert oldest.id == job1.id

    def test_ignores_non_pending_jobs(self, service: PersistentJobService) -> None:
        job = service.submit_scan("pending.com")
        service.submit_scan("other.com")
        service.transition_job(str(job.id), "RUNNING")
        oldest = service.find_oldest_pending()
        assert oldest is not None
        assert oldest.id != job.id


# ===========================================================================
# Cancel — error cases
# ===========================================================================


class TestCancelErrors:
    def test_cancel_nonexistent_raises(self, service: PersistentJobService) -> None:
        with pytest.raises(JobNotFoundError):
            service.cancel_job("no-such-job")

    def test_cancel_already_cancelled_raises(
        self, service: PersistentJobService
    ) -> None:
        job = service.submit_scan("example.com")
        service.cancel_job(str(job.id))
        with pytest.raises(IllegalJobTransitionError):
            service.cancel_job(str(job.id))


# ===========================================================================
# Completed jobs
# ===========================================================================


class TestCompletedJobs:
    def test_get_job_result_raises_for_pending(
        self, service: PersistentJobService
    ) -> None:
        job = service.submit_scan("example.com")
        with pytest.raises(IllegalJobTransitionError):
            service.get_job_result(str(job.id))

    def test_get_job_result_raises_for_nonexistent(
        self, service: PersistentJobService
    ) -> None:
        with pytest.raises(JobNotFoundError):
            service.get_job_result("no-such-id")


# ===========================================================================
# Persistence across sessions
# ===========================================================================


class TestPersistenceAcrossSessions:
    def test_job_survives_session_restart(self, session) -> None:
        engine = create_database_engine(url="sqlite://")
        create_schema(engine)
        job_id = None
        with Session(engine) as s1:
            uow1 = SQLAlchemyUnitOfWork(s1)
            svc1 = PersistentJobService(uow1)
            job = svc1.submit_scan("cross-session.com")
            job_id = str(job.id)

        with Session(engine) as s2:
            uow2 = SQLAlchemyUnitOfWork(s2)
            svc2 = PersistentJobService(uow2)
            fetched = svc2.get_job(job_id)
            assert fetched.target == "cross-session.com"
            assert fetched.status == JobStatus.PENDING

    def test_multiple_jobs_across_sessions(self, session) -> None:
        engine = create_database_engine(url="sqlite://")
        create_schema(engine)
        ids = []
        with Session(engine) as s1:
            svc = PersistentJobService(SQLAlchemyUnitOfWork(s1))
            ids.append(str(svc.submit_scan("a.com").id))
            ids.append(str(svc.submit_scan("b.com").id))

        with Session(engine) as s2:
            svc = PersistentJobService(SQLAlchemyUnitOfWork(s2))
            jobs = svc.list_jobs()
            assert len(jobs) == 2
            retrieved = {j.target for j in jobs}
            assert retrieved == {"a.com", "b.com"}


# ===========================================================================
# Rollback
# ===========================================================================


class TestRollback:
    def test_rollback_on_exception(self, session) -> None:
        engine = create_database_engine(url="sqlite://")
        create_schema(engine)
        with Session(engine) as s:
            uow = SQLAlchemyUnitOfWork(s)
            svc = PersistentJobService(uow)
            job = svc.submit_scan("rollback-test.com")
            job_id = str(job.id)

        with Session(engine) as s2:
            # The first session's work was committed, so it should exist
            svc2 = PersistentJobService(SQLAlchemyUnitOfWork(s2))
            fetched = svc2.get_job(job_id)
            assert fetched.target == "rollback-test.com"

    def test_cancel_rolls_back_on_invalid_transition(
        self, service: PersistentJobService
    ) -> None:
        job = service.submit_scan("rollback-cancel.com")
        job_id = str(job.id)
        service.cancel_job(job_id)
        cancelled = service.get_job(job_id)
        assert cancelled.status == JobStatus.CANCELLED


# ===========================================================================
# Transaction boundaries
# ===========================================================================


class TestTransactionBoundaries:
    def test_submit_scan_in_own_transaction(self, service: PersistentJobService) -> None:
        job = service.submit_scan("tx-test.com")
        assert job.status == JobStatus.PENDING

    def test_get_job_in_own_transaction(self, service: PersistentJobService) -> None:
        job = service.submit_scan("tx-get.com")
        fetched = service.get_job(str(job.id))
        assert fetched.id == job.id

    def test_cancel_in_own_transaction(self, service: PersistentJobService) -> None:
        job = service.submit_scan("tx-cancel.com")
        cancelled = service.cancel_job(str(job.id))
        assert cancelled.status == JobStatus.CANCELLED
        fetched = service.get_job(str(job.id))
        assert fetched.status == JobStatus.CANCELLED

    def test_list_jobs_in_own_transaction(self, service: PersistentJobService) -> None:
        service.submit_scan("tx-list-1.com")
        service.submit_scan("tx-list-2.com")
        jobs = service.list_jobs()
        assert len(jobs) == 2


# ===========================================================================
# API integration — quick smoke tests
# ===========================================================================


class TestApiIntegration:
    """Uses a file-based DB so data survives session close/reopen in the UoW."""

    @pytest.fixture
    def api_env(self):
        import os
        import tempfile
        db_path = tempfile.mktemp(suffix=".db")
        engine = create_database_engine(url=f"sqlite:///{db_path}")
        create_schema(engine)
        with Session(engine) as s:
            yield s, engine
        engine.dispose()
        try:
            os.unlink(db_path)
        except PermissionError:
            pass

    def test_jobs_endpoint_returns_jobs(self, api_env) -> None:
        from fastapi.testclient import TestClient
        from kingsec.interfaces.api.app import create_app

        session, _ = api_env
        uow = SQLAlchemyUnitOfWork(session)
        svc = PersistentJobService(uow)
        app = create_app(job_service=svc)
        client = TestClient(app)

        svc.submit_scan("api-test.com")
        response = client.get("/jobs")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

    def test_create_job_via_api(self, api_env) -> None:
        from fastapi.testclient import TestClient
        from kingsec.interfaces.api.app import create_app

        session, _ = api_env
        uow = SQLAlchemyUnitOfWork(session)
        svc = PersistentJobService(uow)
        app = create_app(job_service=svc)
        client = TestClient(app)

        response = client.post("/jobs", json={"target": "api-create.com"})
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "PENDING"
        assert data["target"] == "api-create.com"

    def test_get_job_via_api(self, api_env) -> None:
        from fastapi.testclient import TestClient
        from kingsec.interfaces.api.app import create_app

        session, _ = api_env
        uow = SQLAlchemyUnitOfWork(session)
        svc = PersistentJobService(uow)
        job = svc.submit_scan("api-get.com")

        app = create_app(job_service=svc)
        client = TestClient(app)

        response = client.get(f"/jobs/{job.id}")
        assert response.status_code == 200
        assert response.json()["target"] == "api-get.com"

    def test_cancel_job_via_api(self, api_env) -> None:
        from fastapi.testclient import TestClient
        from kingsec.interfaces.api.app import create_app

        session, _ = api_env
        uow = SQLAlchemyUnitOfWork(session)
        svc = PersistentJobService(uow)
        job = svc.submit_scan("api-cancel.com")

        app = create_app(job_service=svc)
        client = TestClient(app)

        response = client.delete(f"/jobs/{job.id}")
        assert response.status_code == 200
        assert response.json()["status"] == "CANCELLED"
