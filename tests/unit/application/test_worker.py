from __future__ import annotations

from kingsec.application.jobs import InMemoryJobService, JobStatus
from kingsec.domain.worker import WorkerStatus
from kingsec.infrastructure.worker.polling_worker import PollingWorkerService


class TestPollingWorkerService:
    def setup_method(self) -> None:
        self.job_service = InMemoryJobService()
        self.worker = PollingWorkerService(
            job_service=self.job_service,
            poll_interval_seconds=1,
            heartbeat_interval_seconds=5,
            max_jobs_per_run=1,
        )

    def test_initial_status_is_stopped(self) -> None:
        assert self.worker.status() == WorkerStatus.STOPPED

    def test_start_and_stop(self) -> None:
        self.worker.start_worker()
        assert self.worker.status() == WorkerStatus.RUNNING
        self.worker.stop_worker()
        assert self.worker.status() == WorkerStatus.STOPPED

    def test_execute_next_job_no_pending(self) -> None:
        result = self.worker.execute_next_job()
        assert result is None

    def test_execute_next_job_completes_pending(self) -> None:
        job = self.job_service.submit_scan(target="example.com")
        result = self.worker.execute_next_job()
        assert result == job.id.value
        updated = self.job_service.get_job(job.id.value)
        assert updated.status == JobStatus.COMPLETED

    def test_execute_next_job_processes_oldest_first(self) -> None:
        job1 = self.job_service.submit_scan(target="first.com")
        job2 = self.job_service.submit_scan(target="second.com")
        result = self.worker.execute_next_job()
        assert result == job1.id.value

    def test_heartbeat_after_execution(self) -> None:
        self.job_service.submit_scan(target="example.com")
        self.worker.execute_next_job()
        hb = self.worker.heartbeat()
        assert hb.jobs_completed == 1
        assert hb.jobs_failed == 0
        assert hb.current_job_id is None

    def test_heartbeat_reports_failed_jobs(self) -> None:
        self.job_service.submit_scan(target="example.com")

        class FailingWorker(PollingWorkerService):
            def _run_job(self, job_id: str) -> None:
                msg = "simulated failure"
                raise RuntimeError(msg)

        failing_worker = FailingWorker(job_service=self.job_service)
        failing_worker.execute_next_job()
        hb = failing_worker.heartbeat()
        assert hb.jobs_failed == 1
        assert hb.jobs_completed == 0

    def test_double_start_is_idempotent(self) -> None:
        self.worker.start_worker()
        self.worker.start_worker()
        assert self.worker.status() == WorkerStatus.RUNNING
        self.worker.stop_worker()

    def test_heartbeat_includes_worker_id(self) -> None:
        hb = self.worker.heartbeat()
        assert str(hb.worker_id) == "default-worker"
        assert hb.timestamp is not None


class TestWorkerWithMultipleJobs:
    def setup_method(self) -> None:
        self.job_service = InMemoryJobService()
        self.worker = PollingWorkerService(
            job_service=self.job_service,
            max_jobs_per_run=3,
        )

    def test_max_jobs_per_run_respected(self) -> None:
        for i in range(5):
            self.job_service.submit_scan(target=f"target-{i}.com")
        job_ids = []
        for _ in range(3):
            jid = self.worker.execute_next_job()
            if jid:
                job_ids.append(jid)
        assert len(job_ids) == 3
        remaining = self.job_service.list_jobs()
        pending = [j for j in remaining if j.status == JobStatus.PENDING]
        assert len(pending) == 2
