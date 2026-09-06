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

from typing import Any, NoReturn, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, ReportNotFoundError
from kingsec.application.errors import AssessmentConflictError
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


def raise_persistence_error(message: str, cause: SQLAlchemyError, reference: str) -> NoReturn:
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
    ``Recommendation`` are identity-less value objects in child collections
    that a merge-by-primary-key cannot reliably match. ``ON DELETE CASCADE``
    (SQLite ``PRAGMA foreign_keys=ON``, enabled by every real engine this
    project creates - see ``database.py``) removes the stale children
    before the current state is re-inserted.

    KSEC-107-01 / KSEC-108-01: the replace path is optimistic-locked, the
    same idiom already proven on ``ScheduleORM``/``AssessmentExecutionORM``.
    ``assessment.version`` must be the version this caller originally read
    (via ``get()``) - every mutation path (``CreateAssessment``,
    ``SubmitAssessment``, ``StartAssessment``, scheduled submission, etc.)
    already follows the load-mutate-save pattern, so this requires no
    change to any of them.

    Two cases:

    * ``assessment.version == 0`` - never yet persisted
      (``Assessment.create()``'s own initial state). A plain insert at
      version 1, flushed immediately so a primary-key collision (an
      astronomically unlikely UUID collision, or a caller re-saving an
      unrefreshed version-0 object for an id that was already inserted by
      an earlier save) surfaces here as ``AssessmentConflictError`` rather
      than an unhandled ``IntegrityError`` leaking past this function -
      never a silent overwrite either way.
    * ``assessment.version >= 1`` - this caller previously loaded a real,
      persisted row at exactly that version. The DELETE itself IS the
      atomic concurrency check (Phase 108 Section 31: never a separate
      SELECT-then-compare-in-Python before an unconditional delete-by-id,
      which would reopen the exact TOCTOU gap this closes) - scoped to
      ``WHERE id = ? AND version = ?``. If another writer already replaced
      this row - by advancing its version, or by a genuine
      ``AssessmentRepository.delete()`` - zero rows match and
      ``AssessmentConflictError`` is raised before any INSERT is
      attempted: the stale writer never overwrites, and is never silently
      overwritten. Never retried automatically.

    On success, ``assessment``'s own ``_version`` is advanced in place to
    match what was just durably written. Every caller that follows this
    codebase's established load-mutate-save pattern discards the object
    right after saving it, so this is a no-op for them - but a caller that
    legitimately reuses the SAME object across two sequential saves (e.g.
    ``StartAssessment``, which saves once for RUNNING and again later for
    COMPLETED/FAILED) needs its second save to be checked against the
    version its OWN first save just established, not the stale version it
    was originally loaded at. Mirrors ``mappers.py``'s own reconstitution
    style (``AssessmentORM`` -> ``Assessment`` already reaches into
    "private" fields at the persistence boundary; this is the same trust
    boundary in the other direction).

    Args:
        session: The active session (transaction owned by the caller).
        assessment: The aggregate to persist. Its ``_version`` is mutated
            in place on success (see above).

    Raises:
        AssessmentConflictError: If ``assessment.version >= 1`` and no row
            currently matches both the id and that version.
    """
    if assessment.version == 0:
        orm = assessment_to_orm(assessment)
        orm.version = 1
        session.add(orm)
        try:
            session.flush()
        except IntegrityError as exc:
            raise AssessmentConflictError(
                f"assessment '{assessment.id}' already exists - a fresh-insert attempt "
                "was made for an id that is not new"
            ) from exc
        assessment._version = 1
        return

    result = cast(
        "CursorResult[Any]",
        session.execute(
            delete(AssessmentORM).where(
                AssessmentORM.id == str(assessment.id), AssessmentORM.version == assessment.version
            )
        ),
    )
    if result.rowcount == 0:
        raise AssessmentConflictError(
            f"assessment '{assessment.id}' was modified or deleted by another request since it was last read"
        )
    session.flush()  # ensure the DELETE is applied before the re-INSERT of the same PK
    new_version = assessment.version + 1
    orm = assessment_to_orm(assessment)
    orm.version = new_version
    session.add(orm)
    assessment._version = new_version


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


def list_assessments(
    session: Session,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[Assessment]:
    """Load assessments ordered by created_at DESC with pagination.

    Args:
        session: The active session.
        limit: Maximum number of results.
        offset: Number of results to skip.

    Returns:
        A list of assessments, most recent first. May be empty.
    """
    orms = session.query(AssessmentORM).order_by(AssessmentORM.created_at.desc()).offset(offset).limit(limit).all()
    return [assessment_to_domain(orm) for orm in orms]


def find_assessments_by_schedule_occurrence_id(session: Session, occurrence_id: str) -> list[Assessment]:
    """Load every assessment linked to a schedule occurrence (KSEC-100-01).

    Args:
        session: The active session.
        occurrence_id: The ScheduleOccurrence id to search by.

    Returns:
        Every matching assessment (normally 0 or 1) - callers must not
        assume at most one; a caller-side check across >1 rows is what
        surfaces a corrupted/ambiguous state instead of silently guessing.
    """
    orms = (
        session.query(AssessmentORM)
        .filter(AssessmentORM.schedule_occurrence_id == occurrence_id)
        .order_by(AssessmentORM.created_at.asc())
        .all()
    )
    return [assessment_to_domain(orm) for orm in orms]


def delete_assessment(session: Session, assessment_id: AssessmentId) -> None:
    """Delete an assessment and all its children (cascade).

    Uses the database-level ON DELETE CASCADE to remove findings, evidence,
    recommendations, and (KSEC-110-01) any generated report in one
    operation. The ORM-level cascade (findings only, via AssessmentORM's
    own relationship) provides defense-in-depth; reports rely on the
    database-level FK cascade alone (see ReportORM.assessment_id) since
    they are a separate table/repository with no ORM relationship declared
    on AssessmentORM.

    Args:
        session: The active session.
        assessment_id: The identity of the assessment to delete.

    Raises:
        AssessmentNotFoundError: If no assessment has that id.
    """
    orm = session.get(AssessmentORM, assessment_id.value)
    if orm is None:
        raise AssessmentNotFoundError(assessment_id.value)
    session.delete(orm)
