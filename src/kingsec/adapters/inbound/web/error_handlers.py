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
    │ AssessmentConflictError         │ 409 Conflict                       │
    │ AssessmentExecutionNotReconcila │ 409 Conflict                       │
    │ TooManyConcurrentAssessmentsErr │ 429 Too Many Requests              │
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

import structlog
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from kingsec.application.errors import (
    AccountLinkNotFoundError,
    AgentNotFoundError,
    AlertNotFoundError,
    ApplicationError,
    AssessmentConflictError,
    AssessmentDataCorruptedError,
    AssessmentExecutionNotReconcilableError,
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
    TooManyConcurrentAssessmentsError,
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

# KSEC-87-01: structlog directly (not kingsec.infrastructure.logging.
# get_logger, KingSec's OWN wrapper) - the import-linter "Hexagonal
# layering" contract treats adapters/infrastructure as sibling outer
# layers that must not import each other; every other adapters/inbound/
# web/*.py file that logs (auth.py) uses this exact same direct-structlog
# pattern for the identical reason. structlog's global pipeline is
# already configured once at startup (bootstrap), so this call site
# doesn't need KingSec's own configuration wrapper at all.
_logger = structlog.get_logger("kingsec.adapters.inbound.web.error_handlers")


def admin_operation_error(exc: Exception, operation: str, *, status_code: int = 400) -> HTTPException:
    """Translate an exception caught inside an admin-only route's try block
    into a client-safe ``HTTPException``.

    KSEC-87-01: agent_routes.py/backup_routes.py/plugin_routes.py each had
    ``except Exception as exc: raise HTTPException(..., detail=str(exc))``
    at ~19 call sites - broad enough to also catch genuinely unexpected
    failures (a database error, a bug, a filesystem path) and leak their
    message, even though the failure every one of these routes actually
    expects in normal operation is one of this codebase's own
    deliberately-crafted ``ApplicationError`` subclasses (e.g.
    ``AgentNotFoundError``, ``PluginValidationError``), whose messages are
    already safe by construction - hand-written strings like "Plugin 'x'
    not found", never a wrapped raw filesystem/database exception.

    ``ApplicationError`` (any subclass) keeps its own message verbatim -
    this is the safe, intentional application-layer detail Section 5.2
    warns not to accidentally hide. Anything else is logged here
    (server-side only, never in the response) and replaced with the same
    generic message the existing global catch-all
    (``handle_unhandled_exception`` below) already uses, so an
    unrecognised failure looks identical to the client whether it was
    caught locally by a route or escaped to the global handler.
    """
    if isinstance(exc, ApplicationError):
        return HTTPException(status_code=status_code, detail=str(exc))
    _logger.exception("unexpected error during admin operation", operation=operation)
    return HTTPException(status_code=500, detail=KingSecError.default_user_message)


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


async def handle_assessment_data_corrupted(_request: Request, exc: AssessmentDataCorruptedError) -> JSONResponse:
    """Phase 2B Task 2 Condition 1: the row exists but could not be
    reconstructed - a server-side data problem, not a client error, so
    this is deliberately distinct from the 404 AssessmentNotFoundError
    gets. The exception's own message is safe-by-construction (identifier
    only, never target_value - see AssessmentDataCorruptedError's
    docstring)."""
    return _error_response(500, ErrorCode.UNEXPECTED, str(exc))


async def handle_report_not_found(_request: Request, exc: ReportNotFoundError) -> JSONResponse:
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


async def handle_schedule_conflict(_request: Request, exc: ScheduleConflictError) -> JSONResponse:
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_assessment_conflict(_request: Request, exc: AssessmentConflictError) -> JSONResponse:
    """KSEC-107-01 / KSEC-108-01: a stale writer lost the optimistic-
    concurrency check on Assessment persistence. Same 409 contract as
    ScheduleConflictError/OrganizationConflictError/TeamConflictError -
    the caller must re-fetch and retry, never automatic."""
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_organization_conflict(_request: Request, exc: OrganizationConflictError) -> JSONResponse:
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_team_conflict(_request: Request, exc: TeamConflictError) -> JSONResponse:
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_execution_not_reconcilable(
    _request: Request, exc: AssessmentExecutionNotReconcilableError
) -> JSONResponse:
    """KSEC-105-01: the requested execution is not in one of the two
    Phase 104-approved evidence classes. The exception's own message is
    already safe-by-construction (identifiers and status values only, no
    internals) - same trust boundary as every other ApplicationError here."""
    return _error_response(409, ErrorCode.UNEXPECTED, str(exc))


async def handle_too_many_concurrent_assessments(
    _request: Request, exc: TooManyConcurrentAssessmentsError
) -> JSONResponse:
    return _error_response(429, ErrorCode.UNEXPECTED, str(exc))


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
    # KSEC-87-01: this global catch-all previously returned the generic
    # response with no server-side record of what actually failed - every
    # truly unexpected exception across the ENTIRE app (not just the
    # admin routes admin_operation_error() covers) vanished with zero
    # trace. Logged here, never in the response.
    _logger.exception("unhandled exception reached the global error boundary")
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
    app.exception_handler(AssessmentDataCorruptedError)(handle_assessment_data_corrupted)
    app.exception_handler(ReportNotFoundError)(handle_report_not_found)
    app.exception_handler(LicenseRequiredError)(handle_license_required)
    app.exception_handler(ScheduleConflictError)(handle_schedule_conflict)
    app.exception_handler(OrganizationConflictError)(handle_organization_conflict)
    app.exception_handler(TeamConflictError)(handle_team_conflict)
    app.exception_handler(AssessmentConflictError)(handle_assessment_conflict)
    app.exception_handler(TooManyConcurrentAssessmentsError)(handle_too_many_concurrent_assessments)
    app.exception_handler(AssessmentExecutionNotReconcilableError)(handle_execution_not_reconcilable)

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
