"""Session-level persistence primitives shared across repository styles.

This module is the single source of truth for the correctness-critical
persist/load logic (delete-then-insert for aggregates, merge-upsert for reports,
not-found handling). Two different transaction-ownership styles delegate to it:

    * the autocommit repositories (``repositories.py``) — one transaction per call
    * the session-bound repositories (``unit_of_work.py``) — many operations per
      transaction, owned by a Unit of Work

Keeping the logic here means the delete-then-insert behaviour can never diverge
between the two. These functions operate on a provided ``Session`` and DO NOT
manage transactions (no commit/rollback) — that is the caller's responsibility.
They also do not translate ``SQLAlchemyError``; the transaction-owning caller
does, via :func:`raise_persistence_error`, so commit-time errors are caught too.
"""

from __future__ import annotations

from typing import NoReturn

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, ReportNotFoundError
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


def raise_persistence_error(
    message: str, cause: SQLAlchemyError, reference: str
) -> NoReturn:
    """Translate a SQLAlchemy error into a ``PersistenceError`` and log it.

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


def persist_assessment(session: Session, assessment: Assessment) -> None:
    """Insert or replace an assessment aggregate within the given session.

    Uses DELETE-then-INSERT (full replace) because ``Evidence`` and
    ``Recommendation`` are identity-less value objects in child collections that
    a merge-by-primary-key cannot reliably match. ``ON DELETE CASCADE`` removes
    the stale children before the current state is re-inserted.

    Args:
        session: The active session (transaction owned by the caller).
        assessment: The aggregate to persist.
    """

    existing = session.get(AssessmentORM, str(assessment.id))
    if existing is not None:
        session.delete(existing)
        session.flush()  # ensure the DELETE runs before the re-INSERT of same PK
    session.add(assessment_to_orm(assessment))


def load_assessment(session: Session, assessment_id: AssessmentId) -> Assessment:
    """Load and reconstitute an assessment aggregate, or raise if absent.

    Args:
        session: The active session.
        assessment_id: The identity to load.

    Returns:
        The reconstituted domain aggregate.

    Raises:
        AssessmentNotFoundError: If no assessment has that id.
    """

    orm = session.get(AssessmentORM, assessment_id.value)
    if orm is None:
        raise AssessmentNotFoundError(assessment_id.value)
    # Map while the session is open so lazy child collections load correctly.
    return assessment_to_domain(orm)


def persist_report(session: Session, report: Report) -> None:
    """Insert or update a report snapshot within the given session.

    A report has no value-object child collections (its entries are stored as
    JSON), so a merge-by-primary-key upsert is safe and simplest.

    Args:
        session: The active session.
        report: The report snapshot to persist.
    """

    session.merge(report_to_orm(report))


def load_report(session: Session, assessment_id: AssessmentId) -> Report:
    """Load and reconstitute a report snapshot, or raise if absent.

    Args:
        session: The active session.
        assessment_id: The assessment whose report to load.

    Returns:
        The reconstituted domain report.

    Raises:
        ReportNotFoundError: If no report exists for the assessment.
    """

    orm = session.get(ReportORM, assessment_id.value)
    if orm is None:
        raise ReportNotFoundError(assessment_id.value)
    return report_to_domain(orm)
