"""Outbound port: job runner for background execution.

The application layer defines *what* runs (a callable). The infrastructure
decides *how* it runs (thread, process, async). This port is the seam between
business logic and execution strategy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any


class JobRunner(ABC):
    """Submits callables for background execution."""

    @abstractmethod
    def submit(
        self,
        job_id: str,
        fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Submit a callable for background execution.

        Args:
            job_id: Unique identifier for this job.
            fn: The callable to execute.
            *args: Positional arguments forwarded to ``fn``.
            **kwargs: Keyword arguments forwarded to ``fn``.

        Raises:
            JobRunnerError: If the job cannot be submitted.
        """
        ...

    @abstractmethod
    def is_running(self, job_id: str) -> bool:
        """Return True if a job with this ID is currently executing."""
        ...

    @abstractmethod
    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the runner, optionally waiting for pending jobs.

        Must be idempotent and safe to call from a shutdown hook.
        """
        ...
