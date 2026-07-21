"""MFA domain entities — TOTP secret, recovery codes, and status enums."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class MfaStatus(StrEnum):
    """Whether MFA is enabled for a user."""

    DISABLED = "disabled"
    ENABLED = "enabled"


class RecoveryCodeStatus(StrEnum):
    """Status of a single recovery code."""

    ACTIVE = "active"
    USED = "used"


@dataclass(frozen=True)
class MfaSecret:
    """A user's MFA TOTP secret.

    Never expose ``secret_key`` outside the domain; it must only travel
    between the recovery-code repository and the TOTP service.
    """

    user_id: str
    secret_key: str
    status: MfaStatus = MfaStatus.DISABLED


@dataclass(frozen=True)
class MfaRecoveryCode:
    """A single recovery code — stored hashed, used once."""

    code_hash: str
    status: RecoveryCodeStatus = RecoveryCodeStatus.ACTIVE
