from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from kingsec.domain import Assessment, AssessmentId, Report, ScannerResult, Target

if TYPE_CHECKING:
    from kingsec.application.jobs import ScanJob


# ---------------------------------------------------------------------------
# Define Asset at the port boundary — it is a value object the persistence
# layer knows about but the domain does not currently model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    """A discovered network asset.

    Immutable once recorded.  The asset identifier is opaque to the domain
    — it is assigned by the persistence layer at creation time.
    """

    id: str
    target: Target
    discovered_at: datetime
    tags: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# AssessmentRepository  (exists — kept for completeness)
# ---------------------------------------------------------------------------


class AssessmentRepository(ABC):
    """Persists and retrieves :class:`Assessment` aggregates."""

    @abstractmethod
    def save(self, assessment: Assessment) -> None:
        """Insert or update the given assessment (upsert semantics)."""

    @abstractmethod
    def get(self, assessment_id: AssessmentId) -> Assessment:
        """Return the assessment for the id, or raise AssessmentNotFoundError."""

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Assessment]:
        """Return assessments ordered by created_at DESC with pagination."""

    @abstractmethod
    def delete(self, assessment_id: AssessmentId) -> None:
        """Delete an assessment and all its children.

        Raises:
            AssessmentNotFoundError: If no assessment has that id.
        """


# ---------------------------------------------------------------------------
# ReportRepository  (exists — kept for completeness)
# ---------------------------------------------------------------------------


class ReportRepository(ABC):
    """Persists and retrieves generated :class:`Report` snapshots."""

    @abstractmethod
    def save(self, report: Report) -> None:
        """Store the report (keyed by its assessment id)."""

    @abstractmethod
    def get(self, assessment_id: AssessmentId) -> Report:
        """Return the report for the assessment, or raise ReportNotFoundError."""


# ---------------------------------------------------------------------------
# ScanRepositoryPort  — raw scan results from a single plugin execution
# ---------------------------------------------------------------------------


class ScanRepositoryPort(ABC):
    """Persists and retrieves raw :class:`ScannerResult` objects."""

    @abstractmethod
    def save(self, scan_id: str, result: ScannerResult) -> None:
        """Store a scan result keyed by *scan_id*."""

    @abstractmethod
    def get(self, scan_id: str) -> ScannerResult:
        """Return the scan result for *scan_id*.

        Raises:
            AssessmentNotFoundError: If no scan exists with that id.
        """

    @abstractmethod
    def exists(self, scan_id: str) -> bool:
        """Return True if a scan with *scan_id* is stored."""

    @abstractmethod
    def delete(self, scan_id: str) -> None:
        """Remove a stored scan result.

        Raises:
            AssessmentNotFoundError: If no scan exists with that id.
        """


# ---------------------------------------------------------------------------
# JobRepositoryPort  — scan job metadata (as opposed to scan *results*)
# ---------------------------------------------------------------------------


class JobRepositoryPort(ABC):
    """Persists and retrieves :class:`ScanJob` records."""

    @abstractmethod
    def save(self, job: ScanJob) -> None:
        """Insert or update a scan job (upsert by job id)."""

    @abstractmethod
    def get(self, job_id: str) -> ScanJob:
        """Return the job for *job_id*.

        Raises:
            JobNotFoundError: If no job exists with that id.
        """

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ScanJob]:
        """Return jobs ordered by created_at DESC with pagination."""

    @abstractmethod
    def exists(self, job_id: str) -> bool:
        """Return True if a job with *job_id* is stored."""


# ---------------------------------------------------------------------------
# AssetRepositoryPort  — discovered assets (targets the system knows about)
# ---------------------------------------------------------------------------


class AssetRepositoryPort(ABC):
    """Persists and retrieves discovered :class:`Asset` records."""

    @abstractmethod
    def add(self, asset: Asset) -> None:
        """Insert a new asset (no upsert — use ``update`` to modify)."""

    @abstractmethod
    def get(self, asset_id: str) -> Asset:
        """Return the asset for *asset_id*.

        Raises:
            AssessmentNotFoundError: If no asset exists with that id.
        """

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Asset]:
        """Return assets ordered by discovered_at DESC with pagination."""

    @abstractmethod
    def exists(self, asset_id: str) -> bool:
        """Return True if an asset with *asset_id* is stored."""
