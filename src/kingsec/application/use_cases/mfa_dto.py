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
    """Request to disable MFA for a user.

    ``current_password`` is a KSEC-73-03 step-up credential: possessing a
    valid access token alone must not be sufficient to strip MFA from an
    account, so the self-service caller must re-prove their own password
    immediately before this security-downgrading operation.

    ``is_admin`` is set only by the distinct, already-more-strongly-gated
    admin route (POST /mfa/disable/{user_id}, require_admin_jwt_only) to
    skip the self-service step-up check - an admin cannot know another
    user's password, and admin authority is already a stronger control
    than "possession of an ordinary access token" (the exact threat this
    finding addresses), matching the same is_admin-bypass shape already
    used by check_assessment_access/check_schedule_access/
    check_pipeline_access elsewhere in this application.
    """

    user_id: str
    current_password: str = ""
    is_admin: bool = False


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
    """Request to generate new recovery codes.

    ``current_password`` is a KSEC-73-03 step-up credential - see
    ``DisableMfaRequest``.
    """

    user_id: str
    current_password: str


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
    """Request to replace all recovery codes for a user.

    ``current_password`` is a KSEC-73-03 step-up credential - see
    ``DisableMfaRequest``.
    """

    user_id: str
    current_password: str


@dataclass(frozen=True)
class RotateRecoveryCodesResponse:
    """Response containing new plaintext recovery codes (shown once)."""

    codes: tuple[str, ...]


@dataclass(frozen=True)
class MfaStatusResponse:
    """Current MFA status for a user."""

    enabled: bool
