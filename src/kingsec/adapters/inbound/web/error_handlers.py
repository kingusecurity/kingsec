"""Exception → HTTP status code mapping for the FastAPI adapter.

Boundary policy
    The web adapter translates every exception that escapes a use case into a
    structured JSON error response. No exception type leaks its internal message
    or stack trace to the client. The mapping is:

    ┌─────────────────────────────────┬────────────────────────────────────┐
    │ Exception                       │ HTTP Status                        │
    ├─────────────────────────────────┼────────────────────────────────────┤
    │ InputValidationError            │ 400 Bad Request                    │
    │ AssessmentNotFoundError         │ 404 Not Found                      │
    │ ReportNotFoundError             │ 404 Not Found                      │
    │ *NotFoundError (every other one)│ 404 Not Found                      │
    │ ScheduleConflictError           │ 409 Conflict                       │
    │ OrganizationConflictError       │ 409 Conflict                       │
    │ TeamConflictError               │ 409 Conflict                       │
    │ IllegalStateTransition          │ 409 Conflict                       │
    │ InvariantViolation              │ 422 Unprocessable Entity           │
    │ DomainError (other)             │ 409 Conflict                       │
    │ KingSecError (any subclass)     │ 400 (default), maps by code        │
    │ Exception (unknown)             │ 500 Internal Server Error          │
    └─────────────────────────────────┴────────────────────────────────────┘

    KingSecError subclasses map to the most appropriate status based on their
    stable error code. Unknown exceptions get a generic 500 that leaks nothing.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from kingsec.application.errors import (
    AccountLinkNotFoundError,
    AgentNotFoundError,
    AlertNotFoundError,
    AssessmentNotFoundError,
    AssetNotFoundError,
    BackupNotFoundError,
    CopilotConversationNotFoundError,
    CveNotFoundError,
    DeadLetterEntryNotFoundError,
    ExecutionHistoryNotFoundError,
    ExposureNotFoundError,
    IdentityProviderNotFoundError,
    InputValidationError,
    InvestigationNoteNotFoundError,
    JobLeaseNotFoundError,
    JobNotFoundError,
    JobQueueEntryNotFoundError,
    LicenseRequiredError,
    MfaStepUpAuthenticationError,
    MonitorEventNotFoundError,
    NotificationNotFoundError,
    OrganizationConflictError,
    PipelineNotFoundError,
    PlaybookNotFoundError,
    PluginNotFoundError,
    QueueEntryNotFoundError,
    RecoveryPlanNotFoundError,
    RecoveryTestNotFoundError,
    ReportNotFoundError,
    RestoreNotFoundError,
    RuleNotFoundError,
    ScheduleConflictError,
    ScheduleNotFoundError,
    SnapshotNotFoundError,
    SSOSessionNotFoundError,
    TeamConflictError,
    ThreatFeedNotFoundError,
    VerificationNotFoundError,
    WorkerNotFoundError,
)
from kingsec.application.use_cases.login import AuthenticationError
from kingsec.application.use_cases.refresh_token import TokenRefreshError
from kingsec.application.use_cases.register_user import RegistrationError
from kingsec.application.use_cases.revoke_api_key import (
    ApiKeyNotFoundError,
    ApiKeyUnauthorizedError,
)
from kingsec.domain.errors import (
    DomainError,
    IllegalStateTransition,
    InvariantViolation,
)
from kingsec.domain.rate_limit import RateLimitExceeded
from kingsec.domain.user import PasswordValidationError
from kingsec.shared.errors import ErrorCode, KingSecError


def _error_response(status_code: int, error_code: str, message: str) -> JSONResponse:
    """Build a structured error JSON response with security headers."""
    return JSONResponse(
        status_code=status_code,
        content={"error_code": error_code, "message": message},
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ── Application-layer errors ────────────────────────────────────────────────


async def handle_input_validation_error(_request: Request, exc: InputValidationError) -> JSONResponse:
    return _error_response(400, ErrorCode.VALIDATION, str(exc))


async def handle_assessment_not_found(_request: Request, exc: AssessmentNotFoundError) -> JSONResponse:
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


async def handle_report_not_found(_request: Request, exc: ReportNotFoundError) -> JSONResponse:
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


async def handle_schedule_conflict(_request: Request, exc: ScheduleConflictError) -> JSONResponse:
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_organization_conflict(_request: Request, exc: OrganizationConflictError) -> JSONResponse:
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_team_conflict(_request: Request, exc: TeamConflictError) -> JSONResponse:
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_not_found_error(_request: Request, exc: Exception) -> JSONResponse:
    """Shared 404 handler for every other "resource not found" application error.

    All of these are trivial marker exceptions (no extra fields beyond the
    message), identical in shape to AssessmentNotFoundError/ReportNotFoundError
    above — this generalizes that same handler instead of duplicating it once
    per resource type.
    """
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


# ── Domain-layer errors ─────────────────────────────────────────────────────


async def handle_illegal_state_transition(_request: Request, exc: IllegalStateTransition) -> JSONResponse:
    return _error_response(
        409,
        ErrorCode.UNEXPECTED,
        "The requested operation is not allowed from the current state.",
    )


async def handle_invariant_violation(_request: Request, exc: InvariantViolation) -> JSONResponse:
    return _error_response(
        422,
        ErrorCode.VALIDATION,
        "The request violates a business rule.",
    )


async def handle_rate_limit_exceeded(_request: Request, exc: RateLimitExceeded) -> JSONResponse:
    d = exc.decision
    return JSONResponse(
        status_code=429,
        content={
            "error_code": "KS-RATE-001",
            "message": "rate limit exceeded, try again later",
            "retry_after": d.reset_seconds,
        },
        headers={
            "X-RateLimit-Limit": str(d.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(d.reset_seconds),
            "Retry-After": str(d.reset_seconds),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def handle_password_validation_error(_request: Request, exc: PasswordValidationError) -> JSONResponse:
    return _error_response(400, ErrorCode.VALIDATION, str(exc))


async def handle_authentication_error(_request: Request, exc: AuthenticationError) -> JSONResponse:
    return _error_response(401, ErrorCode.AUTHORIZATION, str(exc))


async def handle_mfa_step_up_authentication_error(
    _request: Request, exc: MfaStepUpAuthenticationError
) -> JSONResponse:
    return _error_response(401, ErrorCode.AUTHORIZATION, str(exc))


async def handle_registration_error(_request: Request, exc: RegistrationError) -> JSONResponse:
    return _error_response(409, ErrorCode.VALIDATION, str(exc))


async def handle_token_refresh_error(_request: Request, exc: TokenRefreshError) -> JSONResponse:
    return _error_response(401, ErrorCode.AUTHORIZATION, str(exc))


async def handle_api_key_not_found(_request: Request, exc: ApiKeyNotFoundError) -> JSONResponse:
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


async def handle_api_key_unauthorized(_request: Request, exc: ApiKeyUnauthorizedError) -> JSONResponse:
    return _error_response(403, ErrorCode.AUTHORIZATION, str(exc))


async def handle_license_required(_request: Request, exc: LicenseRequiredError) -> JSONResponse:
    return _error_response(403, ErrorCode.LICENSE_REQUIRED, str(exc))


async def handle_domain_error(_request: Request, exc: DomainError) -> JSONResponse:
    return _error_response(
        409,
        ErrorCode.UNEXPECTED,
        "The requested operation could not be completed.",
    )


# ── Shared error kernel ─────────────────────────────────────────────────────


_KINGSEC_STATUS_MAP: dict[str, int] = {
    ErrorCode.VALIDATION: 400,
    ErrorCode.AUTHORIZATION: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.EXTERNAL_SERVICE: 502,
    ErrorCode.EXTERNAL_TIMEOUT: 504,
    ErrorCode.SCANNER: 502,
    ErrorCode.PERSISTENCE: 500,
    ErrorCode.CONFIGURATION: 500,
    "KS-REPORT-001": 500,  # ReportGenerationError.code (infrastructure/reporting/errors.py)
}


async def handle_kingsec_error(_request: Request, exc: KingSecError) -> JSONResponse:
    status = _KINGSEC_STATUS_MAP.get(exc.code, 400)
    return _error_response(status, exc.code, exc.user_message)


# ── Catch-all ────────────────────────────────────────────────────────────────


async def handle_unhandled_exception(_request: Request, _exc: Exception) -> JSONResponse:
    return _error_response(
        500,
        ErrorCode.UNEXPECTED,
        KingSecError.default_user_message,
    )


# ── Registration helper ──────────────────────────────────────────────────────


def register_error_handlers(app: object) -> None:
    """Attach all exception handlers to a FastAPI application instance.

    Expects a ``FastAPI`` instance. Typed as ``object`` to avoid importing
    FastAPI at module level (keeps the import in the app factory where it
    belongs).
    """
    from fastapi import FastAPI

    if not isinstance(app, FastAPI):
        raise TypeError(f"expected FastAPI instance, got {type(app).__name__}")

    # Application errors (most specific first).
    app.exception_handler(InputValidationError)(handle_input_validation_error)
    app.exception_handler(AssessmentNotFoundError)(handle_assessment_not_found)
    app.exception_handler(ReportNotFoundError)(handle_report_not_found)
    app.exception_handler(LicenseRequiredError)(handle_license_required)
    app.exception_handler(ScheduleConflictError)(handle_schedule_conflict)
    app.exception_handler(OrganizationConflictError)(handle_organization_conflict)
    app.exception_handler(TeamConflictError)(handle_team_conflict)

    # Every other "resource not found" application error — same 404 contract,
    # previously unregistered and falling through to the generic 500 handler.
    for _not_found_cls in (
        JobNotFoundError,
        NotificationNotFoundError,
        PluginNotFoundError,
        AgentNotFoundError,
        QueueEntryNotFoundError,
        PipelineNotFoundError,
        BackupNotFoundError,
        SnapshotNotFoundError,
        RestoreNotFoundError,
        AssetNotFoundError,
        ExposureNotFoundError,
        MonitorEventNotFoundError,
        AlertNotFoundError,
        RuleNotFoundError,
        CveNotFoundError,
        ThreatFeedNotFoundError,
        CopilotConversationNotFoundError,
        InvestigationNoteNotFoundError,
        PlaybookNotFoundError,
        ExecutionHistoryNotFoundError,
        WorkerNotFoundError,
        JobQueueEntryNotFoundError,
        JobLeaseNotFoundError,
        DeadLetterEntryNotFoundError,
        IdentityProviderNotFoundError,
        SSOSessionNotFoundError,
        AccountLinkNotFoundError,
        ScheduleNotFoundError,
        VerificationNotFoundError,
        RecoveryPlanNotFoundError,
        RecoveryTestNotFoundError,
    ):
        app.exception_handler(_not_found_cls)(handle_not_found_error)

    # Rate limiting.
    app.exception_handler(RateLimitExceeded)(handle_rate_limit_exceeded)

    # Domain errors.
    app.exception_handler(IllegalStateTransition)(handle_illegal_state_transition)
    app.exception_handler(InvariantViolation)(handle_invariant_violation)
    app.exception_handler(PasswordValidationError)(handle_password_validation_error)
    app.exception_handler(AuthenticationError)(handle_authentication_error)
    app.exception_handler(MfaStepUpAuthenticationError)(handle_mfa_step_up_authentication_error)
    app.exception_handler(RegistrationError)(handle_registration_error)
    app.exception_handler(TokenRefreshError)(handle_token_refresh_error)
    app.exception_handler(ApiKeyNotFoundError)(handle_api_key_not_found)
    app.exception_handler(ApiKeyUnauthorizedError)(handle_api_key_unauthorized)
    app.exception_handler(DomainError)(handle_domain_error)

    # Shared error kernel.
    app.exception_handler(KingSecError)(handle_kingsec_error)

    # Catch-all (must be last).
    app.exception_handler(Exception)(handle_unhandled_exception)
