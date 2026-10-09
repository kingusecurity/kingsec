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

import builtins
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application import (
    AssessmentRepository,
    ReportRepository,
)
from kingsec.application.ports import AuthorizationGrantRepository
from kingsec.application.ports.repositories import AssessmentPage, FindingProjection, ReportProjection
from kingsec.domain import Assessment, AssessmentId, AuthorizationGrant, Report
from kingsec.domain.identifiers import AuthorizationGrantId
from kingsec.infrastructure.logging import get_logger

from . import _operations as ops

_logger = get_logger("kingsec.infrastructure.persistence")


class LegacyAssessmentRepository(AssessmentRepository):
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
            ops.raise_persistence_error("failed to save assessment", exc, str(assessment.id))

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
            ops.raise_persistence_error("failed to load assessment", exc, assessment_id.value)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        status: str | None = None,
        order_by: str = "created_at",
        order_dir: str = "desc",
        requesting_user: str = "",
        is_admin: bool = True,
    ) -> AssessmentPage:
        """Return one filtered, ownership-scoped page of assessments.

        Args:
            limit: Maximum number of results (clamped to 200).
            offset: Number of results to skip.

        Returns:
            A page of assessments, most recent first (may be empty), plus
            any unreadable row ids (Phase 2B Task 2 Condition 1).
        """
        clamped_limit = min(max(limit, 1), 200)
        try:
            with self._session_factory() as session:
                return ops.list_assessments(
                    session,
                    limit=clamped_limit,
                    offset=max(offset, 0),
                    search=search,
                    status=status,
                    order_by=order_by,
                    order_dir=order_dir,
                    requesting_user=requesting_user,
                    is_admin=is_admin,
                )
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to list assessments", exc, "-")

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> builtins.list[Assessment]:
        """Return every assessment linked to a schedule occurrence (KSEC-100-01)."""
        try:
            with self._session_factory() as session:
                return ops.find_assessments_by_schedule_occurrence_id(session, occurrence_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to find assessments by schedule occurrence", exc, occurrence_id)

    def find_running(self) -> builtins.list[Assessment]:
        """Return every assessment currently in RUNNING status (Phase 2A FIX 9)."""
        try:
            with self._session_factory() as session:
                return ops.find_running_assessments(session)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to find running assessments", exc, "-")

    def find_running_ids(self) -> builtins.list[str]:
        try:
            with self._session_factory() as session:
                return ops.find_running_ids(session)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to find running assessment ids", exc, "-")

    def force_fail_running(self, assessment_id: str, reason: str) -> bool:
        try:
            with self._session_factory.begin() as session:
                return ops.force_fail_running(session, assessment_id, reason)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to force-fail running assessment", exc, assessment_id)

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
            ops.raise_persistence_error("failed to delete assessment", exc, assessment_id.value)

    def search_findings(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        order_by: str = "discovered_at",
        order_dir: str = "desc",
        limit: int = 50,
        offset: int = 0,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[builtins.list[FindingProjection], int]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.repositories.assessment import SQLAlchemyAssessmentRepository

            return SQLAlchemyAssessmentRepository(session).search_findings(
                severity=severity,
                status=status,
                assessment_id=assessment_id,
                search=search,
                order_by=order_by,
                order_dir=order_dir,
                limit=limit,
                offset=offset,
                requesting_user=requesting_user,
                is_admin=is_admin,
            )


class LegacyReportRepository(ReportRepository):
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
            ops.raise_persistence_error("failed to save report", exc, report.assessment_id)

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
            ops.raise_persistence_error("failed to load report", exc, assessment_id.value)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "generated_at",
        order_dir: str = "desc",
        search: str | None = None,
        severity: str | None = None,
        target: str | None = None,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[builtins.list[ReportProjection], int]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.repositories.report import SQLAlchemyReportRepository

            return SQLAlchemyReportRepository(session).list(
                limit=limit,
                offset=offset,
                order_by=order_by,
                order_dir=order_dir,
                search=search,
                severity=severity,
                target=target,
                requesting_user=requesting_user,
                is_admin=is_admin,
            )

    def count(self) -> int:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.repositories.report import SQLAlchemyReportRepository

            return SQLAlchemyReportRepository(session).count()


class LegacyAuthorizationGrantRepository(AuthorizationGrantRepository):
    """Persists :class:`~kingsec.domain.AuthorizationGrant` aggregates (Phase 4).

    Session-per-call, autocommit - same transaction-ownership style as
    LegacyAssessmentRepository above. Delegates the actual persistence
    logic to the session-bound SQLAlchemyAuthorizationGrantRepository
    rather than duplicating it, so behaviour can never diverge between
    this container-singleton adapter and any future Unit-of-Work caller.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, grant: AuthorizationGrant) -> None:
        from kingsec.infrastructure.persistence.repositories.authorization_grant import (
            SQLAlchemyAuthorizationGrantRepository,
        )

        try:
            with self._session_factory.begin() as session:
                SQLAlchemyAuthorizationGrantRepository(session).save(grant)
            _logger.debug("authorization grant saved", grant_id=grant.id.value)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to save authorization grant", exc, grant.id.value)

    def get(self, grant_id: AuthorizationGrantId) -> AuthorizationGrant:
        from kingsec.infrastructure.persistence.repositories.authorization_grant import (
            SQLAlchemyAuthorizationGrantRepository,
        )

        try:
            with self._session_factory() as session:
                return SQLAlchemyAuthorizationGrantRepository(session).get(grant_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to load authorization grant", exc, grant_id.value)

    def list(self, *, limit: int = 50, offset: int = 0) -> builtins.list[AuthorizationGrant]:
        from kingsec.infrastructure.persistence.repositories.authorization_grant import (
            SQLAlchemyAuthorizationGrantRepository,
        )

        try:
            with self._session_factory() as session:
                return SQLAlchemyAuthorizationGrantRepository(session).list(limit=limit, offset=offset)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to list authorization grants", exc, "-")

    def find_active(self, at: datetime) -> builtins.list[AuthorizationGrant]:
        from kingsec.infrastructure.persistence.repositories.authorization_grant import (
            SQLAlchemyAuthorizationGrantRepository,
        )

        try:
            with self._session_factory() as session:
                return SQLAlchemyAuthorizationGrantRepository(session).find_active(at)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to find active authorization grants", exc, "-")

    def revoke(self, grant_id: AuthorizationGrantId, revoked_at: datetime) -> None:
        from kingsec.infrastructure.persistence.repositories.authorization_grant import (
            SQLAlchemyAuthorizationGrantRepository,
        )

        try:
            with self._session_factory.begin() as session:
                SQLAlchemyAuthorizationGrantRepository(session).revoke(grant_id, revoked_at)
            _logger.debug("authorization grant revoked", grant_id=grant_id.value)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to revoke authorization grant", exc, grant_id.value)
