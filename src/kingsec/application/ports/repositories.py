"""Repository ports — abstract persistence contracts.

These are the "driven" ports (the application drives them). They are expressed
entirely in DOMAIN terms (``Assessment``, ``Report``, ``AssessmentId``) and know
nothing about SQL, files, or any storage technology. An infrastructure adapter
(e.g. a SQLite repository) will subclass these and provide the implementation —
that subclassing is the inward dependency the hexagonal architecture wants.

Contract note on lookups: ``get`` MUST raise the relevant *not-found* error from
``application.errors`` when nothing matches, rather than returning ``None`` — a
missing aggregate is an exceptional condition the caller should handle explicitly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain import Assessment, AssessmentId, Report


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
        """Return assessments ordered by created_at DESC with pagination.

        Args:
            limit: Maximum number of results (default 50, max 200).
            offset: Number of results to skip (default 0).

        Returns:
            A list of assessments, most recent first. May be empty.
        """


class ReportRepository(ABC):
    """Persists and retrieves generated :class:`Report` snapshots."""

    @abstractmethod
    def save(self, report: Report) -> None:
        """Store the report (keyed by its assessment id)."""

    @abstractmethod
    def get(self, assessment_id: AssessmentId) -> Report:
        """Return the report for the assessment, or raise ReportNotFoundError."""
