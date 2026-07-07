"""SQLAlchemy implementations of the application repository ports.

These adapters SUBCLASS the abstract ports from the application layer — the
inward dependency the hexagonal architecture requires. They translate the
domain <-> ORM boundary via ``mappers`` and translate the persistence-error
boundary via ``PersistenceError`` so the application never sees a raw
``SQLAlchemyError``.

Transaction strategy: session-per-operation. Each method opens a short-lived
session/transaction. Aggregates are saved by DELETE-then-INSERT (full replace)
because ``Evidence`` and ``Recommendation`` are identity-less value objects in
child collections, which a merge-by-primary-key cannot reliably match. A future
Unit of Work can compose multiple repository writes into one transaction; it is
intentionally out of scope here so Module 3.2's use cases run unchanged.
"""

from __future__ import annotations

from typing import NoReturn

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application import (
    AssessmentNotFoundError,
    AssessmentRepository,
    ReportNotFoundError,
    ReportRepository,
)
from kingsec.domain import Assessment, AssessmentId, Report
from kingsec.infrastructure.logging import get_logger
from kingsec.shared.errors import PersistenceError, log_exception

from .mappers import (
    assessment_to_domain,
    assessment_to_orm,
    report_to_domain,
    report_to_orm,
)
from .models import AssessmentORM, ReportORM

_logger = get_logger("kingsec.infrastructure.persistence")


def _raise_persistence_error(message: str, cause: SQLAlchemyError, reference: str) -> NoReturn:
    """Translate a SQLAlchemy error into a PersistenceError and log it.

    Keeping the SQLAlchemy exception out of the application layer prevents a
    leaky abstraction: callers depend only on the stable ``PersistenceError``
    contract, never on the persistence technology.

    Args:
        message: Human-readable description of the failed operation.
        cause: The underlying SQLAlchemy exception (preserved as the cause).
        reference: The id involved, for structured log context.

    Raises:
        PersistenceError: Always.
    """

    error = PersistenceError(message, context={"reference": reference}, cause=cause)
    log_exception(_logger, error)
    raise error


class SqlAlchemyAssessmentRepository(AssessmentRepository):
    """Persists :class:`~kingsec.domain.Assessment` aggregates in SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """Initialise the repository.

        Args:
            session_factory: A ``sessionmaker`` bound to the target engine.
        """

        self._session_factory = session_factory

    def save(self, assessment: Assessment) -> None:
        """Insert or update an assessment aggregate (full replace).

        Args:
            assessment: The aggregate to persist.

        Raises:
            PersistenceError: If the database operation fails.
        """

        try:
            # begin() opens a transaction, commits on success, rolls back on error.
            with self._session_factory.begin() as session:
                existing = session.get(AssessmentORM, str(assessment.id))
                if existing is not None:
                    # Delete-then-insert: removes stale children (findings,
                    # evidence, recommendations) via ON DELETE CASCADE before we
                    # re-insert the current aggregate state.
                    session.delete(existing)
                    session.flush()
                session.add(assessment_to_orm(assessment))
            _logger.debug("assessment saved", assessment_id=str(assessment.id))
        except SQLAlchemyError as exc:
            _raise_persistence_error(
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
                orm = session.get(AssessmentORM, assessment_id.value)
                if orm is None:
                    raise AssessmentNotFoundError(assessment_id.value)
                # Map while the session is open so lazy children load correctly.
                return assessment_to_domain(orm)
        except SQLAlchemyError as exc:
            _raise_persistence_error(
                "failed to load assessment", exc, assessment_id.value
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
        """Insert or update a report snapshot (keyed by assessment id).

        Args:
            report: The report snapshot to persist.

        Raises:
            PersistenceError: If the database operation fails.
        """

        try:
            with self._session_factory.begin() as session:
                # A report has no value-object child collections (entries are
                # JSON), so a merge-by-PK upsert is safe and simplest here.
                session.merge(report_to_orm(report))
            _logger.debug("report saved", assessment_id=report.assessment_id)
        except SQLAlchemyError as exc:
            _raise_persistence_error(
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
                orm = session.get(ReportORM, assessment_id.value)
                if orm is None:
                    raise ReportNotFoundError(assessment_id.value)
                return report_to_domain(orm)
        except SQLAlchemyError as exc:
            _raise_persistence_error(
                "failed to load report", exc, assessment_id.value
            )
