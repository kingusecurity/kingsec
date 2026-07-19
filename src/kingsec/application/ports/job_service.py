from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.jobs import ScanJob, ScanJobResult


class JobServicePort(ABC):
    """Port for async scan job lifecycle management.

    Implementations handle job creation, state transitions, cancellation,
    and result storage.  The API layer depends on this port, never on
    a concrete implementation.
    """

    @abstractmethod
    def submit_scan(self, target: str, config: dict | None = None) -> ScanJob:
        """Create a new scan job in PENDING state.

        Args:
            target: The scan target (hostname, IP, URL).
            config: Optional configuration dict (e.g. selected scanners).

        Returns:
            The newly created ``ScanJob``.

        Raises:
            InputValidationError: If the target is empty or invalid.
        """
        ...

    @abstractmethod
    def get_job(self, job_id: str) -> ScanJob:
        """Retrieve a job by its identifier.

        Args:
            job_id: The job UUID string.

        Returns:
            The matching ``ScanJob``.

        Raises:
            JobNotFoundError: If no job exists for *job_id*.
        """
        ...

    @abstractmethod
    def list_jobs(self) -> list[ScanJob]:
        """Return every known job, newest first."""
        ...

    @abstractmethod
    def cancel_job(self, job_id: str) -> ScanJob:
        """Request cancellation of a pending or running job.

        Args:
            job_id: The job UUID string.

        Returns:
            The updated ``ScanJob`` (status → CANCELLED).

        Raises:
            JobNotFoundError: If no job exists for *job_id*.
            IllegalJobTransitionError: If the job is already in a
                terminal state (COMPLETED, FAILED, CANCELLED).
        """
        ...

    @abstractmethod
    def get_job_result(self, job_id: str) -> ScanJobResult:
        """Retrieve the result of a completed job.

        Args:
            job_id: The job UUID string.

        Returns:
            The ``ScanJobResult`` containing findings.

        Raises:
            JobNotFoundError: If no job exists for *job_id*.
            IllegalJobTransitionError: If the job has not completed yet.
        """
        ...
