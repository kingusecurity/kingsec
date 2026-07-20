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
    def mark_used(self, user_id: str, code_hash: str) -> None:
        """Mark a single recovery code as used."""

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """Remove all recovery codes for a user."""
