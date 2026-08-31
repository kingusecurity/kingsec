"""Port for recovery code persistence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from kingsec.domain.mfa import MfaRecoveryCode


class RecoveryCodeRepository(ABC):
    """Append-only store for hashed recovery codes."""

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> Sequence[MfaRecoveryCode]:
        """List all recovery codes for a user."""

    @abstractmethod
    def save_batch(self, user_id: str, codes: Sequence[MfaRecoveryCode]) -> None:
        """Replace all recovery codes for a user."""

    @abstractmethod
    def mark_used(self, user_id: str, code_hash: str) -> bool:
        """Atomically transition one code from ACTIVE to USED.

        KSEC-73-04: this MUST be a single, atomic, database-level
        conditional operation (e.g. ``UPDATE ... WHERE status='active'``,
        checking the affected-row count) - not a separate read-then-write
        pair - so that at most one of two concurrent callers presenting
        the same code can ever receive ``True``.

        Returns:
            ``True`` if this call performed the ACTIVE -> USED
            transition. ``False`` if the code does not exist for this
            user or was already USED - callers MUST treat ``False`` as
            "invalid code", not silently proceed as if it succeeded.
        """

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """Remove all recovery codes for a user."""
