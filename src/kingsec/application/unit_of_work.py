"""Unit of Work port — the transaction-boundary abstraction.

A Unit of Work groups several repository operations into one atomic transaction:
either every write inside the block is committed, or none is.

Pattern::

    uow = uow_factory()
    with uow:
        repo.save(...)
        repo.save(...)
        uow.commit()

On any exception inside the ``with`` block, or on a clean exit without an
explicit ``commit()``, the Unit of Work rolls back and closes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType


class UnitOfWorkPort(ABC):
    """Atomic transaction boundary for persistence operations.

    Concrete implementations manage a real database connection / session.
    """

    def __init__(self) -> None:
        self._committed: bool = False

    @abstractmethod
    def begin(self) -> None:
        """Start a new transaction.

        Must be idempotent — calling ``begin()`` twice without an intervening
        ``commit()`` or ``rollback()`` is an error.
        """

    @abstractmethod
    def commit(self) -> None:
        """Persist all changes made since ``begin()``.

        After a successful ``commit()`` the transaction is ended.  Call
        ``begin()`` again to start a new one.
        """
        self._committed = True

    @abstractmethod
    def rollback(self) -> None:
        """Discard all changes made since ``begin()`` and end the transaction."""

    @abstractmethod
    def close(self) -> None:
        """Release underlying resources (connection, session, etc.).

        Must be idempotent and safe to call multiple times.
        """

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> UnitOfWorkPort:
        self._committed = False
        self.begin()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        if exc_type is not None:
            self.rollback()
        elif not self._committed:
            self.rollback()
        self.close()
        return False  # do not suppress any exception
