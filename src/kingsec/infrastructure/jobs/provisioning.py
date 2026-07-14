"""DI wiring for the job runner infrastructure."""

from __future__ import annotations

from kingsec.application.ports.outbound.job_runner import JobRunner

from .thread_runner import ThreadJobRunner


def register_jobs(container: object, *, max_workers: int = 4) -> None:
    """Register the job runner and add a shutdown hook.

    Args:
        container: The DI container to register on.
        max_workers: Maximum concurrent background jobs.
    """

    runner = ThreadJobRunner(max_workers=max_workers)
    container.register_instance(JobRunner, runner)
    container.add_shutdown_hook(lambda: runner.shutdown(wait=True))
