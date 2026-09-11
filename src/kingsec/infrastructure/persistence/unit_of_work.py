"""SQLAlchemy Unit of Work and session-bound repositories.

The Unit of Work owns a single ``Session`` for the lifetime of a ``with`` block
and exposes repositories bound to that session. Those repositories perform their
work through the shared primitives in ``_operations`` but never commit — the Unit
of Work owns the transaction and commits (or rolls back) exactly once.

Contrast with ``repositories.py``: those adapters own their transaction per call
(autocommit) and are what Module 3.2's single-write use cases resolve today. The
Unit of Work here is for use cases that must write several aggregates atomically.

Two UoW styles coexist:
    * ``SqlAlchemyUnitOfWork`` — legacy: owns a ``sessionmaker``, creates its own
      session on ``__enter__``, implements the old ``UnitOfWork`` port.
    * ``SQLAlchemyUnitOfWork`` — new: receives an existing ``Session``, implements
      ``UnitOfWorkPort``, exposes all five repositories (assessment, report, scan,
      job, asset) bound to the shared session.
"""

from __future__ import annotations

import builtins
from types import TracebackType
from typing import Protocol

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application import (
    AssessmentRepository,
    ReportRepository,
    UnitOfWork,
    UnitOfWorkFactory,
)
from kingsec.application.ports.repositories import FindingProjection, ReportProjection
from kingsec.application.unit_of_work import UnitOfWorkPort
from kingsec.domain import Assessment, AssessmentId, Report
from kingsec.infrastructure.logging import get_logger

from . import _operations as ops
from .repositories import (
    SQLAlchemyAssessmentRepository,
    SQLAlchemyAssetRepository,
    SQLAlchemyJobRepository,
    SQLAlchemyReportRepository,
    SQLAlchemyScanRepository,
)

_logger = get_logger("kingsec.infrastructure.persistence")


class _SessionBoundAssessmentRepository(AssessmentRepository):
    """Assessment repository that operates on a caller-owned session (no commit)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, assessment: Assessment) -> None:
        try:
            ops.persist_assessment(self._session, assessment)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to save assessment", exc, str(assessment.id))

    def get(self, assessment_id: AssessmentId) -> Assessment:
        try:
            return ops.load_assessment(self._session, assessment_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to load assessment", exc, assessment_id.value)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> builtins.list[Assessment]:
        try:
            return ops.list_assessments(self._session, limit=min(max(limit, 1), 200), offset=max(offset, 0))
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to list assessments", exc, "-")

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> builtins.list[Assessment]:
        try:
            return ops.find_assessments_by_schedule_occurrence_id(self._session, occurrence_id)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to find assessments by schedule occurrence", exc, occurrence_id)

    def find_running(self) -> builtins.list[Assessment]:
        try:
            return ops.find_running_assessments(self._session)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to find running assessments", exc, "-")

    def delete(self, assessment_id: AssessmentId) -> None:
        try:
            ops.delete_assessment(self._session, assessment_id)
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
        repo = SQLAlchemyAssessmentRepository(self._session)
        return repo.search_findings(
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


class _SessionBoundReportRepository(ReportRepository):
    """Report repository that operates on a caller-owned session (no commit)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, report: Report) -> None:
        try:
            ops.persist_report(self._session, report)
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to save report", exc, report.assessment_id)

    def get(self, assessment_id: AssessmentId) -> Report:
        try:
            return ops.load_report(self._session, assessment_id)
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
        repo = SQLAlchemyReportRepository(self._session)
        return repo.list(
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
        repo = SQLAlchemyReportRepository(self._session)
        return repo.count()


class SqlAlchemyUnitOfWork(UnitOfWork):
    """A SQLAlchemy-backed atomic transaction boundary.

    Opens a fresh session on entry, exposes session-bound repositories, and — per
    the safe-by-default contract — rolls back anything not explicitly committed
    when the block exits.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """Initialise the Unit of Work.

        Args:
            session_factory: A ``sessionmaker`` bound to the target engine.
        """
        self._session_factory = session_factory
        self._session: Session | None = None
        self._committed: bool = False

    def __enter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._session_factory()
        self.assessments = _SessionBoundAssessmentRepository(self._session)
        self.reports = _SessionBoundReportRepository(self._session)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._session is None:
            raise RuntimeError("unit of work was not entered — no session to exit")
        try:
            if not self._committed:
                self._session.rollback()
        finally:
            self._session.close()
            self._session = None

    def commit(self) -> None:
        """Commit the transaction, translating any failure to PersistenceError.

        Raises:
            PersistenceError: If the commit fails at the database level.
        """
        if self._session is None:
            raise RuntimeError("unit of work was not entered — cannot commit")
        try:
            self._session.commit()
            self._committed = True
        except SQLAlchemyError as exc:
            ops.raise_persistence_error("failed to commit transaction", exc, "-")

    def rollback(self) -> None:
        """Discard all changes made in this transaction."""
        if self._session is None:
            raise RuntimeError("unit of work was not entered — cannot rollback")
        self._session.rollback()


class SqlAlchemyUnitOfWorkFactory(UnitOfWorkFactory):
    """Produces a fresh :class:`SqlAlchemyUnitOfWork` per transaction."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def __call__(self) -> UnitOfWork:
        return SqlAlchemyUnitOfWork(self._session_factory)


def create_unit_of_work_factory(
    session_factory: sessionmaker[Session],
) -> UnitOfWorkFactory:
    """Build a Unit of Work factory bound to a session factory.

    Args:
        session_factory: A ``sessionmaker`` bound to the target engine.

    Returns:
        A ``UnitOfWorkFactory`` that yields fresh Units of Work.
    """
    return SqlAlchemyUnitOfWorkFactory(session_factory)


class _SupportsRegistration(Protocol):  # pragma: no cover - typing helper only
    def register_instance(self, service_type: type, instance: object) -> None: ...


def register_unit_of_work(
    container: _SupportsRegistration, session_factory: sessionmaker[Session]
) -> UnitOfWorkFactory:
    """Register a Unit of Work factory on the bootstrap container.

    Bound to the ``UnitOfWorkFactory`` port so use cases can resolve it and
    create a fresh transaction per operation.

    Args:
        container: The bootstrap DI container (duck-typed: needs
            ``register_instance``). The Module 2.4 ``Container`` satisfies this.
        session_factory: A ``sessionmaker`` bound to the target engine.

    Returns:
        The registered ``UnitOfWorkFactory`` (for the caller's reference).
    """
    factory = create_unit_of_work_factory(session_factory)
    # Duck-typed call keeps infrastructure decoupled from the bootstrap layer.
    register = container.register_instance
    register(UnitOfWorkFactory, factory)
    _logger.info("unit of work registered", backend="sqlite")
    return factory


# ===========================================================================
#  SQLAlchemyUnitOfWork  — new style, implements UnitOfWorkPort (Phase 7.4)
# ===========================================================================


class SQLAlchemyUnitOfWork(UnitOfWorkPort):
    """Unit of Work backed by an injected SQLAlchemy :class:`Session`.

    All five repositories share the same session, so writes performed through
    one repository are immediately visible through any other inside the same
    transaction.

    Usage::

        uow = SQLAlchemyUnitOfWork(session)
        with uow:
            uow.assessment_repository.save(assessment)
            uow.report_repository.save(report)
            uow.commit()
    """

    def __init__(self, session: Session) -> None:
        super().__init__()
        self._session = session
        self._active = False

    # -- repositories (lazy, all bound to self._session) ---------------------

    @property
    def assessment_repository(self) -> SQLAlchemyAssessmentRepository:
        return SQLAlchemyAssessmentRepository(self._session)

    @property
    def report_repository(self) -> SQLAlchemyReportRepository:
        return SQLAlchemyReportRepository(self._session)

    @property
    def scan_repository(self) -> SQLAlchemyScanRepository:
        return SQLAlchemyScanRepository(self._session)

    @property
    def job_repository(self) -> SQLAlchemyJobRepository:
        return SQLAlchemyJobRepository(self._session)

    @property
    def asset_repository(self) -> SQLAlchemyAssetRepository:
        return SQLAlchemyAssetRepository(self._session)

    # -- transaction lifecycle -----------------------------------------------

    def begin(self) -> None:
        if self._active:
            raise RuntimeError("Unit of Work is already active — call commit or rollback first")
        self._session.connection()  # ensure a connection/transaction is acquired
        self._active = True

    def commit(self) -> None:
        if not self._active:
            raise RuntimeError("Unit of Work is not active — call begin() first")
        self._session.commit()
        self._active = False
        UnitOfWorkPort.commit(self)

    def rollback(self) -> None:
        if not self._active:
            return
        self._session.rollback()
        self._active = False

    def close(self) -> None:
        self._session.close()
        self._active = False
