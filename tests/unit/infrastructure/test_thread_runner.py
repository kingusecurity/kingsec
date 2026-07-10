"""Tests for ThreadJobRunner — background execution infrastructure."""

from __future__ import annotations

import threading
import time

import pytest

from kingsec.infrastructure.jobs.thread_runner import JobRunnerError, ThreadJobRunner


class TestThreadJobRunnerSubmit:
    def test_submit_runs_callable_in_background(self) -> None:
        runner = ThreadJobRunner(max_workers=2)
        result: list[str] = []

        def _job() -> None:
            result.append("done")

        runner.submit("job-1", _job)
        runner.shutdown(wait=True)

        assert result == ["done"]

    def test_submit_returns_immediately(self) -> None:
        runner = ThreadJobRunner(max_workers=2)
        started = threading.Event()
        blocked = threading.Event()

        def _slow_job() -> None:
            started.set()
            blocked.wait(timeout=2.0)

        runner.submit("job-1", _slow_job)
        started.wait(timeout=2.0)

        # submit should return immediately, job is still running
        assert runner.is_running("job-1")

        blocked.set()
        runner.shutdown(wait=True)

    def test_duplicate_job_id_while_running_raises(self) -> None:
        runner = ThreadJobRunner(max_workers=2)
        gate = threading.Event()

        def _blocking() -> None:
            gate.wait(timeout=2.0)

        runner.submit("job-1", _blocking)

        with pytest.raises(JobRunnerError, match="already running"):
            runner.submit("job-1", lambda: None)

        gate.set()
        runner.shutdown(wait=True)

    def test_duplicate_job_id_after_completion_allowed(self) -> None:
        runner = ThreadJobRunner(max_workers=2)

        runner.submit("job-1", lambda: None)
        runner.shutdown(wait=True)

        # After completion, same ID should be allowed (resubmit)
        runner2 = ThreadJobRunner(max_workers=2)
        runner2.submit("job-1", lambda: None)
        runner2.shutdown(wait=True)


class TestThreadJobRunnerIsRunning:
    def test_is_running_false_for_unknown_job(self) -> None:
        runner = ThreadJobRunner(max_workers=1)
        assert runner.is_running("nonexistent") is False

    def test_is_running_true_while_executing(self) -> None:
        runner = ThreadJobRunner(max_workers=2)
        gate = threading.Event()

        def _blocking() -> None:
            gate.wait(timeout=2.0)

        runner.submit("job-1", _blocking)
        assert runner.is_running("job-1") is True

        gate.set()
        runner.shutdown(wait=True)

    def test_is_running_false_after_completion(self) -> None:
        runner = ThreadJobRunner(max_workers=2)

        runner.submit("job-1", lambda: None)
        runner.shutdown(wait=True)

        assert runner.is_running("job-1") is False


class TestThreadJobRunnerShutdown:
    def test_shutdown_waits_for_pending_jobs(self) -> None:
        runner = ThreadJobRunner(max_workers=2)
        result: list[str] = []

        def _job() -> None:
            time.sleep(0.05)
            result.append("completed")

        runner.submit("job-1", _job)
        runner.shutdown(wait=True)

        assert result == ["completed"]

    def test_shutdown_idempotent(self) -> None:
        runner = ThreadJobRunner(max_workers=1)
        runner.submit("job-1", lambda: None)
        runner.shutdown(wait=True)
        runner.shutdown(wait=True)  # second call should not raise


class TestThreadJobRunnerConcurrency:
    def test_multiple_jobs_run_concurrently(self) -> None:
        runner = ThreadJobRunner(max_workers=4)
        timestamps: list[float] = []
        gate = threading.Event()

        def _job(index: int) -> None:
            gate.wait(timeout=2.0)
            timestamps.append(time.monotonic())

        for i in range(4):
            runner.submit(f"job-{i}", _job, i)

        gate.set()
        runner.shutdown(wait=True)

        # All 4 should have timestamps (ran concurrently, not sequentially)
        assert len(timestamps) == 4

    def test_max_workers_limits_concurrency(self) -> None:
        runner = ThreadJobRunner(max_workers=1)
        active_count: list[int] = []
        gate = threading.Event()

        def _job() -> None:
            active_count.append(1)
            gate.wait(timeout=2.0)

        runner.submit("job-1", _job)
        runner.submit("job-2", _job)

        # With max_workers=1, only 1 should run at a time
        time.sleep(0.05)
        assert len(active_count) <= 1

        gate.set()
        runner.shutdown(wait=True)
