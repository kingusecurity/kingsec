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
    ApplicationError,
    AssessmentNotFoundError,
    InputValidationError,
    ReportNotFoundError,
)
from kingsec.domain.errors import (
    DomainError,
    IllegalStateTransition,
    InvariantViolation,
)
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


async def handle_input_validation_error(
    _request: Request, exc: InputValidationError
) -> JSONResponse:
    return _error_response(400, ErrorCode.VALIDATION, str(exc))


async def handle_assessment_not_found(
    _request: Request, exc: AssessmentNotFoundError
) -> JSONResponse:
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


async def handle_report_not_found(
    _request: Request, exc: ReportNotFoundError
) -> JSONResponse:
    return _error_response(404, ErrorCode.NOT_FOUND, str(exc))


# ── Domain-layer errors ─────────────────────────────────────────────────────


async def handle_illegal_state_transition(
    _request: Request, exc: IllegalStateTransition
) -> JSONResponse:
    return _error_response(
        409,
        ErrorCode.UNEXPECTED,
        "The requested operation is not allowed from the current state.",
    )


async def handle_invariant_violation(
    _request: Request, exc: InvariantViolation
) -> JSONResponse:
    return _error_response(
        422,
        ErrorCode.VALIDATION,
        "The request violates a business rule.",
    )


async def handle_domain_error(
    _request: Request, exc: DomainError
) -> JSONResponse:
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
}


async def handle_kingsec_error(
    _request: Request, exc: KingSecError
) -> JSONResponse:
    status = _KINGSEC_STATUS_MAP.get(exc.code, 400)
    return _error_response(status, exc.code, exc.user_message)


# ── Catch-all ────────────────────────────────────────────────────────────────


async def handle_unhandled_exception(
    _request: Request, _exc: Exception
) -> JSONResponse:
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

    assert isinstance(app, FastAPI)  # noqa: S101 - programmer error, not runtime

    # Application errors (most specific first).
    app.exception_handler(InputValidationError)(handle_input_validation_error)
    app.exception_handler(AssessmentNotFoundError)(handle_assessment_not_found)
    app.exception_handler(ReportNotFoundError)(handle_report_not_found)

    # Domain errors.
    app.exception_handler(IllegalStateTransition)(handle_illegal_state_transition)
    app.exception_handler(InvariantViolation)(handle_invariant_violation)
    app.exception_handler(DomainError)(handle_domain_error)

    # Shared error kernel.
    app.exception_handler(KingSecError)(handle_kingsec_error)

    # Catch-all (must be last).
    app.exception_handler(Exception)(handle_unhandled_exception)
