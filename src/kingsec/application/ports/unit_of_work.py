"""Unit of Work ports — the transaction-boundary abstraction.

A Unit of Work groups several repository operations into ONE atomic transaction:
either every write inside the block is committed, or none is. Use cases that must
change more than one aggregate consistently depend on this abstraction; the
infrastructure layer provides the concrete, database-specific implementation.

Semantics (safe by default): changes persist only if ``commit()`` is called
before the ``with`` block exits. On any exception, or on a clean exit without an
explicit commit, the Unit of Work rolls back. This makes accidental partial
writes impossible — forgetting to commit loses the work loudly rather than
persisting half of it.

Example:
    uow = uow_factory()
    with uow:
        assessment = uow.assessments.get(assessment_id)
        assessment.complete()
        uow.assessments.save(assessment)
        uow.reports.save(report)
        uow.commit()   # both writes commit together, or neither does
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType

from .repositories import AssessmentRepository, ReportRepository


class UnitOfWork(ABC):
    """An atomic transaction boundary exposing session-bound repositories.

    Concrete implementations bind :attr:`assessments` and :attr:`reports` to a
    single underlying transaction when the context is entered.

    Attributes:
        assessments: Repository for assessment aggregates within this transaction.
        reports: Repository for report snapshots within this transaction.
    """

    assessments: AssessmentRepository
    reports: ReportRepository

    @abstractmethod
    def __enter__(self) -> UnitOfWork:
        """Begin the transaction and expose the session-bound repositories."""

    @abstractmethod
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        """End the transaction: roll back anything not explicitly committed.

        Returns:
            ``False`` so that exceptions raised inside the block are never
            suppressed.
        """

    @abstractmethod
    def commit(self) -> None:
        """Commit all changes made inside this Unit of Work."""

    @abstractmethod
    def rollback(self) -> None:
        """Discard all changes made inside this Unit of Work."""


class UnitOfWorkFactory(ABC):
    """Creates a fresh :class:`UnitOfWork` per transaction.

    A Unit of Work wraps exactly one transaction, so use cases request a new one
    each time rather than sharing a single instance. Depending on a factory
    (instead of a shared UoW) keeps transactions isolated — essential once
    multiple requests run concurrently.
    """

    @abstractmethod
    def __call__(self) -> UnitOfWork:
        """Return a new, unentered Unit of Work."""
