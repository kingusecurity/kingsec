from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from kingsec.application.errors import IllegalJobTransitionError, JobNotFoundError
from kingsec.application.jobs import (
    InMemoryJobService,
    JobStatus,
    ScanJobResult,
    validate_transition,
)

# ===========================================================================
# JobStatus — enum values + terminal check
# ===========================================================================


class TestJobStatus:
    def test_values(self) -> None:
        assert JobStatus.PENDING.value == "PENDING"
        assert JobStatus.RUNNING.value == "RUNNING"
        assert JobStatus.COMPLETED.value == "COMPLETED"
        assert JobStatus.FAILED.value == "FAILED"
        assert JobStatus.CANCELLED.value == "CANCELLED"

    def test_terminal_states(self) -> None:
        assert not JobStatus.PENDING.is_terminal
        assert not JobStatus.RUNNING.is_terminal
        assert JobStatus.COMPLETED.is_terminal
        assert JobStatus.FAILED.is_terminal
        assert JobStatus.CANCELLED.is_terminal


# ===========================================================================
# validate_transition — state machine rules
# ===========================================================================


class TestValidateTransition:
    def test_pending_to_running(self) -> None:
        validate_transition(JobStatus.PENDING, JobStatus.RUNNING)

    def test_pending_to_cancelled(self) -> None:
        validate_transition(JobStatus.PENDING, JobStatus.CANCELLED)

    def test_running_to_completed(self) -> None:
        validate_transition(JobStatus.RUNNING, JobStatus.COMPLETED)

    def test_running_to_failed(self) -> None:
        validate_transition(JobStatus.RUNNING, JobStatus.FAILED)

    def test_running_to_cancelled(self) -> None:
        validate_transition(JobStatus.RUNNING, JobStatus.CANCELLED)

    # -- illegal transitions -------------------------------------------------

    def test_pending_to_completed_raises(self) -> None:
        with pytest.raises(IllegalJobTransitionError):
            validate_transition(JobStatus.PENDING, JobStatus.COMPLETED)

    def test_pending_to_failed_raises(self) -> None:
        with pytest.raises(IllegalJobTransitionError):
            validate_transition(JobStatus.PENDING, JobStatus.FAILED)

    def test_running_to_pending_raises(self) -> None:
        with pytest.raises(IllegalJobTransitionError):
            validate_transition(JobStatus.RUNNING, JobStatus.PENDING)

    def test_completed_to_anything_raises(self) -> None:
        for target in JobStatus:
            if target is JobStatus.COMPLETED:
                continue
            with pytest.raises(IllegalJobTransitionError):
                validate_transition(JobStatus.COMPLETED, target)

    def test_failed_to_anything_raises(self) -> None:
        for target in JobStatus:
            if target is JobStatus.FAILED:
                continue
            with pytest.raises(IllegalJobTransitionError):
                validate_transition(JobStatus.FAILED, target)

    def test_cancelled_to_anything_raises(self) -> None:
        for target in JobStatus:
            if target is JobStatus.CANCELLED:
                continue
            with pytest.raises(IllegalJobTransitionError):
                validate_transition(JobStatus.CANCELLED, target)


# ===========================================================================
# InMemoryJobService
# ===========================================================================


class TestInMemoryJobServiceSubmit:
    def setup_method(self) -> None:
        self.service = InMemoryJobService()

    def test_submit_returns_pending_job(self) -> None:
        job = self.service.submit_scan(target="example.com")
        assert job.status is JobStatus.PENDING
        assert job.target == "example.com"
        assert job.config == {}

    def test_submit_with_config(self) -> None:
        config = {"scanners": ["nuclei"]}
        job = self.service.submit_scan(target="example.com", config=config)
        assert job.config == config

    def test_submit_generates_uuid(self) -> None:
        job = self.service.submit_scan(target="example.com")
        parsed = uuid.UUID(job.id.value, version=4)
        assert parsed.version == 4

    def test_submit_sets_created_at(self) -> None:
        job = self.service.submit_scan(target="example.com")
        assert isinstance(job.created_at, datetime)
        assert job.created_at.tzinfo is not None


class TestInMemoryJobServiceGetJob:
    def setup_method(self) -> None:
        self.service = InMemoryJobService()
        self.job = self.service.submit_scan(target="example.com")

    def test_get_existing_job(self) -> None:
        fetched = self.service.get_job(self.job.id.value)
        assert fetched.id.value == self.job.id.value
        assert fetched.target == "example.com"

    def test_get_nonexistent_job_raises(self) -> None:
        with pytest.raises(JobNotFoundError):
            self.service.get_job("no-such-job")


class TestInMemoryJobServiceListJobs:
    def setup_method(self) -> None:
        self.service = InMemoryJobService()

    def test_list_empty(self) -> None:
        assert self.service.list_jobs() == []

    def test_list_returns_all_jobs(self) -> None:
        j1 = self.service.submit_scan(target="a.com")
        j2 = self.service.submit_scan(target="b.com")
        jobs = self.service.list_jobs()
        assert len(jobs) == 2
        ids = [j.id.value for j in jobs]
        assert j2.id.value in ids
        assert j1.id.value in ids

    def test_list_newest_first(self) -> None:
        j1 = self.service.submit_scan(target="a.com")
        j2 = self.service.submit_scan(target="b.com")
        jobs = self.service.list_jobs()
        assert jobs[0].id.value == j2.id.value
        assert jobs[1].id.value == j1.id.value


class TestInMemoryJobServiceCancel:
    def setup_method(self) -> None:
        self.service = InMemoryJobService()
        self.job = self.service.submit_scan(target="example.com")

    def test_cancel_pending_job(self) -> None:
        cancelled = self.service.cancel_job(self.job.id.value)
        assert cancelled.status is JobStatus.CANCELLED
        assert cancelled.updated_at > cancelled.created_at

    def test_cancel_running_job(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        cancelled = self.service.cancel_job(self.job.id.value)
        assert cancelled.status is JobStatus.CANCELLED

    def test_cancel_nonexistent_raises(self) -> None:
        with pytest.raises(JobNotFoundError):
            self.service.cancel_job("no-such-job")

    def test_cancel_completed_job_raises(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        self.service.transition_job(self.job.id.value, JobStatus.COMPLETED)
        with pytest.raises(IllegalJobTransitionError):
            self.service.cancel_job(self.job.id.value)

    def test_cancel_failed_job_raises(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        self.service.transition_job(self.job.id.value, JobStatus.FAILED)
        with pytest.raises(IllegalJobTransitionError):
            self.service.cancel_job(self.job.id.value)

    def test_cancel_already_cancelled_raises(self) -> None:
        self.service.cancel_job(self.job.id.value)
        with pytest.raises(IllegalJobTransitionError):
            self.service.cancel_job(self.job.id.value)


class TestInMemoryJobServiceTransition:
    def setup_method(self) -> None:
        self.service = InMemoryJobService()
        self.job = self.service.submit_scan(target="example.com")

    def test_pending_to_running(self) -> None:
        job = self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        assert job.status is JobStatus.RUNNING

    def test_running_to_completed(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        job = self.service.transition_job(self.job.id.value, JobStatus.COMPLETED)
        assert job.status is JobStatus.COMPLETED

    def test_running_to_failed(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        job = self.service.transition_job(self.job.id.value, JobStatus.FAILED)
        assert job.status is JobStatus.FAILED

    def test_illegal_transition_raises(self) -> None:
        with pytest.raises(IllegalJobTransitionError):
            self.service.transition_job(self.job.id.value, JobStatus.COMPLETED)

    def test_transition_nonexistent_raises(self) -> None:
        with pytest.raises(JobNotFoundError):
            self.service.transition_job("no-such-job", JobStatus.RUNNING)


class TestInMemoryJobServiceGetResult:
    def setup_method(self) -> None:
        self.service = InMemoryJobService()
        self.job = self.service.submit_scan(target="example.com")

    def test_get_result_for_completed_job(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        self.service.transition_job(self.job.id.value, JobStatus.COMPLETED)
        result = ScanJobResult(
            job_id=self.job.id.value,
            completed_at=datetime.now(UTC),
            findings=({"port": 80, "status": "open"},),
        )
        self.service.store_result(self.job.id.value, result)
        fetched = self.service.get_job_result(self.job.id.value)
        assert fetched.job_id == self.job.id.value
        assert len(fetched.findings) == 1
        assert fetched.findings[0]["port"] == 80

    def test_get_result_non_completed_raises(self) -> None:
        with pytest.raises(IllegalJobTransitionError):
            self.service.get_job_result(self.job.id.value)

    def test_get_result_nonexistent_raises(self) -> None:
        with pytest.raises(JobNotFoundError):
            self.service.get_job_result("no-such-job")

    def test_get_result_running_raises(self) -> None:
        self.service.transition_job(self.job.id.value, JobStatus.RUNNING)
        with pytest.raises(IllegalJobTransitionError):
            self.service.get_job_result(self.job.id.value)

    def test_get_result_cancelled_raises(self) -> None:
        self.service.cancel_job(self.job.id.value)
        with pytest.raises(IllegalJobTransitionError):
            self.service.get_job_result(self.job.id.value)


class TestInMemoryJobServiceThreadSafety:
    def test_concurrent_submission(self) -> None:
        import concurrent.futures

        service = InMemoryJobService()

        def submit() -> str:
            job = service.submit_scan(target="example.com")
            return job.id.value

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(submit) for _ in range(50)]
            ids = {f.result() for f in futures}

        assert len(ids) == 50
        jobs = service.list_jobs()
        assert len(jobs) == 50
