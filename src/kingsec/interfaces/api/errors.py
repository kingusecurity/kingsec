"""Global exception handlers for the KingSec REST API.

Maps every known exception type to a standard ``ApiError`` response.
No business logic, no infrastructure — only HTTP error translation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from .models import ApiError


# ============================================================================
# Error factory
# ============================================================================


def _error_response(
    request: Request,
    status_code: int,
    error_type: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Build a standard ``ApiError`` JSON response."""
    error = ApiError(
        timestamp=datetime.now(timezone.utc),
        request_id=str(uuid.uuid4()),
        status=status_code,
        error=error_type,
        message=message,
        path=request.url.path,
        details=details,
    )
    return JSONResponse(status_code=status_code, content=error.model_dump(mode="json"))


# ============================================================================
# Individual handlers
# ============================================================================


def _handle(request: Request, exc: Exception, status_code: int, error_type: str) -> JSONResponse:
    return _error_response(request, status_code, error_type, str(exc))


def _handle_kingsec_validation(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "VALIDATION_ERROR", str(exc))


def _handle_not_found(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_404_NOT_FOUND, "NOT_FOUND", str(exc))


def _handle_forbidden(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_403_FORBIDDEN, "FORBIDDEN", str(exc))


def _handle_conflict(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_409_CONFLICT, "CONFLICT", str(exc))


def _handle_internal(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", str(exc))


def _handle_timeout(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_504_GATEWAY_TIMEOUT, "TIMEOUT_ERROR", str(exc))


def _handle_unavailable(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(request, status.HTTP_503_SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", str(exc))


# ============================================================================
# Registration
# ============================================================================


def register_error_handlers(app: FastAPI) -> None:
    """Register all exception handlers on the given FastAPI application.

    Must be called after the app is created but before it is exposed to
    the server — typically inside ``create_app()``.
    """

    # ── 403 ────────────────────────────────────────────────────────────
    from kingsec.shared.errors import AuthorizationError

    @app.exception_handler(PermissionError)
    async def _permission_error(request: Request, exc: PermissionError) -> JSONResponse:
        return _error_response(request, status.HTTP_403_FORBIDDEN, "FORBIDDEN", "Permission denied.")

    @app.exception_handler(AuthorizationError)
    async def _authorization_error(request: Request, exc: AuthorizationError) -> JSONResponse:
        return _error_response(request, status.HTTP_403_FORBIDDEN, "FORBIDDEN", exc.user_message)

    # ── 404 / 405 ──────────────────────────────────────────────────────
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error_response(request, exc.status_code, "HTTP_ERROR", exc.detail)

    from kingsec.shared.errors import ResourceNotFoundError
    from kingsec.application.errors import AssessmentNotFoundError, ReportNotFoundError

    @app.exception_handler(KeyError)
    async def _key_error(request: Request, exc: KeyError) -> JSONResponse:
        return _error_response(request, status.HTTP_404_NOT_FOUND, "NOT_FOUND", f"Resource not found: {exc}")

    @app.exception_handler(FileNotFoundError)
    async def _file_not_found(request: Request, exc: FileNotFoundError) -> JSONResponse:
        return _error_response(request, status.HTTP_404_NOT_FOUND, "NOT_FOUND", "The requested resource was not found.")

    @app.exception_handler(ResourceNotFoundError)
    async def _resource_not_found(request: Request, exc: ResourceNotFoundError) -> JSONResponse:
        return _error_response(request, status.HTTP_404_NOT_FOUND, "NOT_FOUND", exc.user_message)

    @app.exception_handler(AssessmentNotFoundError)
    async def _assessment_not_found(request: Request, exc: AssessmentNotFoundError) -> JSONResponse:
        return _error_response(request, status.HTTP_404_NOT_FOUND, "NOT_FOUND", str(exc))

    @app.exception_handler(ReportNotFoundError)
    async def _report_not_found(request: Request, exc: ReportNotFoundError) -> JSONResponse:
        return _error_response(request, status.HTTP_404_NOT_FOUND, "NOT_FOUND", str(exc))

    # ── 409 ────────────────────────────────────────────────────────────
    from kingsec.application.errors import ScannerDuplicateError
    from kingsec.domain.errors import IllegalStateTransition

    @app.exception_handler(ScannerDuplicateError)
    async def _scanner_duplicate(request: Request, exc: ScannerDuplicateError) -> JSONResponse:
        return _error_response(request, status.HTTP_409_CONFLICT, "CONFLICT", str(exc))

    @app.exception_handler(IllegalStateTransition)
    async def _illegal_state(request: Request, exc: IllegalStateTransition) -> JSONResponse:
        return _error_response(request, status.HTTP_409_CONFLICT, "CONFLICT", str(exc))

    # ── 422 ────────────────────────────────────────────────────────────
    from kingsec.application.errors import InputValidationError
    from kingsec.domain.errors import InvariantViolation
    from kingsec.shared.errors import ValidationError

    @app.exception_handler(InputValidationError)
    async def _input_validation(request: Request, exc: InputValidationError) -> JSONResponse:
        return _error_response(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "VALIDATION_ERROR", str(exc))

    @app.exception_handler(ValidationError)
    async def _validation_error(request: Request, exc: ValidationError) -> JSONResponse:
        return _error_response(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "VALIDATION_ERROR", exc.user_message)

    @app.exception_handler(ValueError)
    async def _value_error(request: Request, exc: ValueError) -> JSONResponse:
        return _error_response(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "VALIDATION_ERROR", str(exc))

    @app.exception_handler(InvariantViolation)
    async def _invariant_violation(request: Request, exc: InvariantViolation) -> JSONResponse:
        return _error_response(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "VALIDATION_ERROR", str(exc))

    # ── 500 ────────────────────────────────────────────────────────────
    from kingsec.application.errors import ScannerPluginError

    @app.exception_handler(NotImplementedError)
    async def _not_implemented(request: Request, exc: NotImplementedError) -> JSONResponse:
        return _error_response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "NOT_IMPLEMENTED", str(exc))

    @app.exception_handler(ScannerPluginError)
    async def _scanner_plugin(request: Request, exc: ScannerPluginError) -> JSONResponse:
        return _error_response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "SCANNER_ERROR", str(exc))

    # ── 503 ────────────────────────────────────────────────────────────
    from kingsec.application.errors import ScannerUnavailableError

    @app.exception_handler(ScannerUnavailableError)
    async def _scanner_unavailable(request: Request, exc: ScannerUnavailableError) -> JSONResponse:
        return _error_response(request, status.HTTP_503_SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", str(exc))

    # ── 504 ────────────────────────────────────────────────────────────
    from kingsec.application.errors import ScannerTimeoutError

    @app.exception_handler(TimeoutError)
    async def _timeout_error(request: Request, exc: TimeoutError) -> JSONResponse:
        return _error_response(request, status.HTTP_504_GATEWAY_TIMEOUT, "TIMEOUT_ERROR", "The request timed out.")

    @app.exception_handler(ScannerTimeoutError)
    async def _scanner_timeout(request: Request, exc: ScannerTimeoutError) -> JSONResponse:
        return _error_response(request, status.HTTP_504_GATEWAY_TIMEOUT, "SCANNER_TIMEOUT", str(exc))

    # ── Catch-all ──────────────────────────────────────────────────────
    from kingsec.application.errors import ApplicationError
    from kingsec.domain.errors import DomainError

    @app.exception_handler(DomainError)
    async def _domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return _error_response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "DOMAIN_ERROR", str(exc))

    @app.exception_handler(ApplicationError)
    async def _application_error(request: Request, exc: ApplicationError) -> JSONResponse:
        return _error_response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "APPLICATION_ERROR", str(exc))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An unexpected error occurred. Please try again or contact support.",
        )
