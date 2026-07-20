"""Port for RFC 6238 TOTP operations."""
from __future__ import annotations

from abc import ABC, abstractmethod


class TotpServicePort(ABC):
    """Abstract port for TOTP secret management and code verification."""

    @abstractmethod
    def generate_secret(self) -> str:
        """Generate a new random Base32 TOTP secret."""

    @abstractmethod
    def generate_uri(self, secret: str, username: str, issuer: str = "KingSec") -> str:
        """Generate a provisioning URI for QR codes (otpauth://)."""

    @abstractmethod
    def verify(self, secret: str, code: str, drift: int = 1) -> bool:
        """Verify a TOTP code against a secret with allowed clock drift."""
