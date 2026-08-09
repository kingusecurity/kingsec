"""DTOs for MFA use cases."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EnableMfaRequest:
    """Request to enable MFA for a user."""

    user_id: str


@dataclass(frozen=True)
class EnableMfaResponse:
    """Response containing the TOTP secret and provisioning URI."""

    secret: str
    uri: str


@dataclass(frozen=True)
class DisableMfaRequest:
    """Request to disable MFA for a user."""

    user_id: str


@dataclass(frozen=True)
class VerifyMfaCodeRequest:
    """Request to complete a login pending MFA, with a TOTP code.

    ``pending_token`` is the short-lived token Login issued after password
    verification succeeded - not the username/password again. It identifies
    the in-progress login attempt and proves the first factor already
    passed.
    """

    pending_token: str
    totp_code: str


@dataclass(frozen=True)
class VerifyMfaCodeResponse:
    """Response from successful MFA verification (JWT issued)."""

    user_id: str
    username: str
    role: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


@dataclass(frozen=True)
class GenerateRecoveryCodesRequest:
    """Request to generate new recovery codes."""

    user_id: str


@dataclass(frozen=True)
class GenerateRecoveryCodesResponse:
    """Response containing plaintext recovery codes (shown once)."""

    codes: tuple[str, ...]


@dataclass(frozen=True)
class UseRecoveryCodeRequest:
    """Request to complete a login pending MFA, with a recovery code.

    ``pending_token`` is the short-lived token Login issued after password
    verification succeeded - not the username/password again. See
    ``VerifyMfaCodeRequest`` for the same shape used with a TOTP code.
    """

    pending_token: str
    recovery_code: str


@dataclass(frozen=True)
class UseRecoveryCodeResponse:
    """Response from successful recovery code authentication."""

    user_id: str
    username: str
    role: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


@dataclass(frozen=True)
class RotateRecoveryCodesRequest:
    """Request to replace all recovery codes for a user."""

    user_id: str


@dataclass(frozen=True)
class RotateRecoveryCodesResponse:
    """Response containing new plaintext recovery codes (shown once)."""

    codes: tuple[str, ...]


@dataclass(frozen=True)
class MfaStatusResponse:
    """Current MFA status for a user."""

    enabled: bool
