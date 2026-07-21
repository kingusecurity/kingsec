"""Integration tests for SQLAlchemyJobRepository.

Exercises every JobRepositoryPort method against a real SQLite database.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application import JobNotFoundError
from kingsec.application.job import JobId
from kingsec.application.jobs import JobStatus, ScanJob
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyJobRepository,
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
    return SQLAlchemyJobRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_job(
    *,
    job_id: str = "job-1",
    target: str = "example.com",
    status: JobStatus = JobStatus.PENDING,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> ScanJob:
    now = datetime.now(UTC)
    return ScanJob(
        id=JobId(job_id),
        target=target,
        config={"timeout": 30},
        status=status,
        created_at=created_at or now,
        updated_at=updated_at or now,
    )


# ===========================================================================
# Save & Get
# ===========================================================================


class TestSaveAndGet:
    def test_save_and_get(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        job = make_job()
        repo.save(job)
        session.flush()

        loaded = repo.get("job-1")
        assert loaded.id == job.id
        assert loaded.target == "example.com"
        assert loaded.status == JobStatus.PENDING

    def test_get_returns_domain_object(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        job = make_job()
        repo.save(job)
        session.flush()

        loaded = repo.get("job-1")
        assert isinstance(loaded, ScanJob)

    def test_get_non_existent_raises(self, repo: SQLAlchemyJobRepository) -> None:
        with pytest.raises(JobNotFoundError):
            repo.get("nonexistent")

    def test_save_persists_to_database(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        job = make_job()
        repo.save(job)
        session.flush()

        from kingsec.infrastructure.persistence.models import JobModel
        orm = session.get(JobModel, "job-1")
        assert orm is not None
        assert orm.status == "PENDING"


# ===========================================================================
# Update / Overwrite
# ===========================================================================


class TestUpdate:
    def test_save_twice_overwrites(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        job1 = make_job(status=JobStatus.PENDING)
        repo.save(job1)
        session.flush()

        job2 = make_job(status=JobStatus.COMPLETED)
        repo.save(job2)
        session.flush()

        loaded = repo.get("job-1")
        assert loaded.status == JobStatus.COMPLETED

    def test_overwrite_preserves_target(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        job = make_job(target="original.com")
        repo.save(job)
        session.flush()

        updated = make_job(target="updated.com")
        repo.save(updated)
        session.flush()

        loaded = repo.get("job-1")
        assert loaded.target == "updated.com"


# ===========================================================================
# Exists
# ===========================================================================


class TestExists:
    def test_exists_returns_true_when_present(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        repo.save(make_job())
        session.flush()
        assert repo.exists("job-1") is True

    def test_exists_returns_false_when_absent(self, repo: SQLAlchemyJobRepository) -> None:
        assert repo.exists("nonexistent") is False

    def test_exists_after_save_then_unknown(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        assert repo.exists("job-1") is False
        repo.save(make_job())
        session.flush()
        assert repo.exists("job-1") is True


# ===========================================================================
# List
# ===========================================================================


class TestList:
    def test_list_empty(self, repo: SQLAlchemyJobRepository) -> None:
        assert repo.list() == []

    def test_list_returns_all(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        repo.save(make_job(job_id="job-1", target="a.com"))
        repo.save(make_job(job_id="job-2", target="b.com"))
        session.flush()

        result = repo.list()
        assert len(result) == 2

    def test_list_ordered_by_created_at_desc(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        early = datetime(2025, 1, 1, tzinfo=UTC)
        late = datetime(2026, 1, 1, tzinfo=UTC)
        repo.save(make_job(job_id="job-1", created_at=early, updated_at=early))
        repo.save(make_job(job_id="job-2", created_at=late, updated_at=late))
        session.flush()

        result = repo.list()
        assert result[0].id.value == "job-2"
        assert result[1].id.value == "job-1"

    def test_list_respects_limit(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        for i in range(5):
            repo.save(make_job(job_id=f"job-{i}", target=f"h{i}.com"))
        session.flush()

        result = repo.list(limit=2)
        assert len(result) == 2

    def test_list_respects_offset(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        repo.save(make_job(job_id="job-1"))
        repo.save(make_job(job_id="job-2"))
        repo.save(make_job(job_id="job-3"))
        session.flush()

        result = repo.list(limit=10, offset=1)
        assert len(result) == 2


# ===========================================================================
# Mapping correctness
# ===========================================================================


class TestMapping:
    def test_round_trip_preserves_status(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        for status in JobStatus:
            job = make_job(job_id=f"job-{status.value}", status=status)
            repo.save(job)
        session.flush()

        for status in JobStatus:
            loaded = repo.get(f"job-{status.value}")
            assert loaded.status == status

    def test_round_trip_preserves_timestamps(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        created_at = datetime(2025, 6, 15, 14, 30, 0, 123456, tzinfo=UTC)
        updated_at = datetime(2025, 6, 16, 10, 0, 0, tzinfo=UTC)
        job = make_job(created_at=created_at, updated_at=updated_at)
        repo.save(job)
        session.flush()

        loaded = repo.get("job-1")
        assert loaded.created_at == created_at
        assert loaded.updated_at == updated_at
        assert loaded.created_at.tzinfo is not None
        assert loaded.updated_at.tzinfo is not None

    def test_round_trip_unicode(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        job = make_job(target="über-unicod€.com")
        repo.save(job)
        session.flush()

        loaded = repo.get("job-1")
        assert loaded.target == "über-unicod€.com"


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_multiple_jobs(self, repo: SQLAlchemyJobRepository, session: Session) -> None:
        repo.save(make_job(job_id="job-1", target="a.com"))
        repo.save(make_job(job_id="job-2", target="b.com"))
        session.flush()

        assert repo.get("job-1").target == "a.com"
        assert repo.get("job-2").target == "b.com"
        assert len(repo.list()) == 2

    def test_rollback_discards_save(self, engine) -> None:
        with Session(engine) as s:
            repo = SQLAlchemyJobRepository(s)
            repo.save(make_job())
            s.rollback()

        with Session(engine) as s2:
            repo2 = SQLAlchemyJobRepository(s2)
            assert repo2.exists("job-1") is False

    def test_new_session_reads_committed(self, engine, repo: SQLAlchemyJobRepository, session: Session) -> None:
        repo.save(make_job())
        session.commit()

        with Session(engine) as s2:
            repo2 = SQLAlchemyJobRepository(s2)
            assert repo2.exists("job-1") is True

    def test_empty_database(self, repo: SQLAlchemyJobRepository) -> None:
        assert repo.list() == []
        assert repo.exists("anything") is False
        with pytest.raises(JobNotFoundError):
            repo.get("anything")
