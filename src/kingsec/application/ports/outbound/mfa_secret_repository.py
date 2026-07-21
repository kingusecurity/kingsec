"""Port for MFA secret persistence."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.mfa import MfaSecret


class MfaSecretRepository(ABC):
    """Storage for per-user MFA TOTP secrets."""

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> MfaSecret | None:
        """Look up a user's MFA secret."""

    @abstractmethod
    def save(self, secret: MfaSecret) -> None:
        """Create or update a user's MFA secret."""

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """Remove a user's MFA secret (disables MFA)."""
