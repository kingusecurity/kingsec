"""SQLAlchemy implementations of the application repository ports (autocommit).

These adapters SUBCLASS the abstract ports from the application layer — the
inward dependency the hexagonal architecture requires — and own their
transaction per call (session-per-operation). They are what Module 3.2's
single-write use cases resolve today.

The correctness-critical persist/load logic (delete-then-insert, merge-upsert,
not-found, error translation) lives in ``_operations`` and is shared with the
session-bound repositories used by the Unit of Work, so the behaviour can never
diverge between the two transaction-ownership styles. These classes add only the
per-call transaction boundary and debug logging around those primitives.
"""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application import (
    AssessmentRepository,
    ReportRepository,
)
from kingsec.domain import Assessment, AssessmentId, Report
from kingsec.infrastructure.logging import get_logger

from . import _operations as ops

_logger = get_logger("kingsec.infrastructure.persistence")


class SqlAlchemyAssessmentRepository(AssessmentRepository):
    """Persists :class:`~kingsec.domain.Assessment` aggregates in SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """Initialise the repository.

        Args:
            session_factory: A ``sessionmaker`` bound to the target engine.
        """

        self._session_factory = session_factory

    def save(self, assessment: Assessment) -> None:
        """Insert or update an assessment aggregate in its own transaction.

        Args:
            assessment: The aggregate to persist.

        Raises:
            PersistenceError: If the database operation fails.
        """

        try:
            # begin() opens a transaction, commits on success, rolls back on error.
            with self._session_factory.begin() as session:
                ops.persist_assessment(session, assessment)
            _logger.debug("assessment saved", assessment_id=str(assessment.id))
        except SQLAlchemyError as exc:
            ops.raise_persistence_error(
                "failed to save assessment", exc, str(assessment.id)
            )

    def get(self, assessment_id: AssessmentId) -> Assessment:
        """Load an assessment aggregate by id.

        Args:
            assessment_id: The identity to load.

        Returns:
            The reconstituted domain aggregate.

        Raises:
            AssessmentNotFoundError: If no assessment has that id.
            PersistenceError: If the database operation fails.
        """

        try:
            with self._session_factory() as session:
                return ops.load_assessment(session, assessment_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error(
                "failed to load assessment", exc, assessment_id.value
            )

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Assessment]:
        """Return assessments ordered by created_at DESC with pagination.

        Args:
            limit: Maximum number of results (clamped to 200).
            offset: Number of results to skip.

        Returns:
            A list of assessments, most recent first. May be empty.
        """

        clamped_limit = min(max(limit, 1), 200)
        try:
            with self._session_factory() as session:
                return ops.list_assessments(
                    session, limit=clamped_limit, offset=max(offset, 0)
                )
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to list assessments", exc, "-")

    def delete(self, assessment_id: AssessmentId) -> None:
        """Delete an assessment and all its children (cascade).

        Args:
            assessment_id: The identity of the assessment to delete.

        Raises:
            AssessmentNotFoundError: If no assessment has that id.
            PersistenceError: If the database operation fails.
        """

        try:
            with self._session_factory.begin() as session:
                ops.delete_assessment(session, assessment_id)
            _logger.debug("assessment deleted", assessment_id=assessment_id.value)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error(
                "failed to delete assessment", exc, assessment_id.value
            )


class SqlAlchemyReportRepository(ReportRepository):
    """Persists :class:`~kingsec.domain.Report` snapshots in SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """Initialise the repository.

        Args:
            session_factory: A ``sessionmaker`` bound to the target engine.
        """

        self._session_factory = session_factory

    def save(self, report: Report) -> None:
        """Insert or update a report snapshot in its own transaction.

        Args:
            report: The report snapshot to persist.

        Raises:
            PersistenceError: If the database operation fails.
        """

        try:
            with self._session_factory.begin() as session:
                ops.persist_report(session, report)
            _logger.debug("report saved", assessment_id=report.assessment_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error(
                "failed to save report", exc, report.assessment_id
            )

    def get(self, assessment_id: AssessmentId) -> Report:
        """Load a report snapshot by assessment id.

        Args:
            assessment_id: The assessment whose report to load.

        Returns:
            The reconstituted domain report.

        Raises:
            ReportNotFoundError: If no report exists for the assessment.
            PersistenceError: If the database operation fails.
        """

        try:
            with self._session_factory() as session:
                return ops.load_report(session, assessment_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error(
                "failed to load report", exc, assessment_id.value
            )
