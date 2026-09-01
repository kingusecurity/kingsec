"""Tests for exception → HTTP status mapping."""

from __future__ import annotations

import pytest

from kingsec.adapters.inbound.web.error_handlers import (
    _KINGSEC_STATUS_MAP,
    _error_response,
    handle_assessment_not_found,
    handle_domain_error,
    handle_illegal_state_transition,
    handle_input_validation_error,
    handle_invariant_violation,
    handle_kingsec_error,
    handle_report_not_found,
    handle_schedule_conflict,
    handle_unhandled_exception,
)
from kingsec.application.errors import (
    AssessmentNotFoundError,
    InputValidationError,
    ReportNotFoundError,
    ScheduleConflictError,
)
from kingsec.domain.errors import (
    DomainError,
    IllegalStateTransition,
    InvariantViolation,
)
from kingsec.infrastructure.reporting.errors import ReportGenerationError
from kingsec.shared.errors import (
    ErrorCode,
    ExternalServiceError,
    KingSecError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)


class TestErrorResponseHelper:
    def test_status_code(self) -> None:
        resp = _error_response(404, "KS-RES-001", "Not found")
        assert resp.status_code == 404

    def test_body_format(self) -> None:
        resp = _error_response(400, "KS-VAL-001", "Bad input")
        import json

        body = json.loads(resp.body)
        assert body["error_code"] == "KS-VAL-001"
        assert body["message"] == "Bad input"

    def test_security_headers(self) -> None:
        resp = _error_response(500, "KS-ERR-000", "Error")
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"


class TestApplicationErrorHandlers:
    @pytest.mark.asyncio
    async def test_input_validation_returns_400(self) -> None:
        exc = InputValidationError("bad field")
        resp = await handle_input_validation_error(None, exc)
        assert resp.status_code == 400
        import json

        body = json.loads(resp.body)
        assert body["error_code"] == ErrorCode.VALIDATION

    @pytest.mark.asyncio
    async def test_assessment_not_found_returns_404(self) -> None:
        exc = AssessmentNotFoundError("asmt-001")
        resp = await handle_assessment_not_found(None, exc)
        assert resp.status_code == 404
        import json

        body = json.loads(resp.body)
        assert body["error_code"] == ErrorCode.NOT_FOUND

    @pytest.mark.asyncio
    async def test_report_not_found_returns_404(self) -> None:
        exc = ReportNotFoundError("asmt-001")
        resp = await handle_report_not_found(None, exc)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_schedule_conflict_returns_409(self) -> None:
        """KSEC-85-02: an optimistic-lock conflict on save() is a 409, not
        a 500 - the caller lost a race, not the server."""
        exc = ScheduleConflictError("schedule 'sch-1' was modified by another request")
        resp = await handle_schedule_conflict(None, exc)
        assert resp.status_code == 409
        import json

        body = json.loads(resp.body)
        assert "modified by another request" in body["message"]


class TestDomainErrorHandlers:
    @pytest.mark.asyncio
    async def test_illegal_state_transition_returns_409(self) -> None:
        exc = IllegalStateTransition("cannot start", current="draft", attempted="start")
        resp = await handle_illegal_state_transition(None, exc)
        assert resp.status_code == 409
        import json

        body = json.loads(resp.body)
        assert "not allowed" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_invariant_violation_returns_422(self) -> None:
        exc = InvariantViolation("empty title")
        resp = await handle_invariant_violation(None, exc)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_generic_domain_error_returns_409(self) -> None:
        exc = DomainError("something")
        resp = await handle_domain_error(None, exc)
        assert resp.status_code == 409


class TestKingSecErrorHandler:
    @pytest.mark.asyncio
    async def test_validation_error_returns_400(self) -> None:
        exc = ValidationError("internal detail", user_message="Bad input.")
        resp = await handle_kingsec_error(None, exc)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_resource_not_found_returns_404(self) -> None:
        exc = ResourceNotFoundError("not found")
        resp = await handle_kingsec_error(None, exc)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_external_service_returns_502(self) -> None:
        exc = ExternalServiceError("provider down")
        resp = await handle_kingsec_error(None, exc)
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_persistence_error_returns_500(self) -> None:
        exc = PersistenceError("db issue")
        resp = await handle_kingsec_error(None, exc)
        assert resp.status_code == 500

    @pytest.mark.asyncio
    async def test_unknown_code_defaults_to_400(self) -> None:
        exc = KingSecError("something")
        resp = await handle_kingsec_error(None, exc)
        assert resp.status_code == 400


class TestUnhandledExceptionHandler:
    @pytest.mark.asyncio
    async def test_returns_500_with_safe_message(self) -> None:
        exc = ValueError("leaky detail")
        resp = await handle_unhandled_exception(None, exc)
        assert resp.status_code == 500
        import json

        body = json.loads(resp.body)
        assert body["error_code"] == ErrorCode.UNEXPECTED
        assert "leaky detail" not in body["message"]
        assert body["message"] == KingSecError.default_user_message

    @pytest.mark.asyncio
    async def test_no_internal_details_leaked(self) -> None:
        exc = RuntimeError("database password is xyz")
        resp = await handle_unhandled_exception(None, exc)
        import json

        body = json.loads(resp.body)
        assert "xyz" not in body["message"]


class TestStatusMap:
    def test_all_expected_codes_present(self) -> None:
        expected_codes = {
            ErrorCode.VALIDATION,
            ErrorCode.AUTHORIZATION,
            ErrorCode.NOT_FOUND,
            ErrorCode.EXTERNAL_SERVICE,
            ErrorCode.EXTERNAL_TIMEOUT,
            ErrorCode.SCANNER,
            ErrorCode.PERSISTENCE,
            ErrorCode.CONFIGURATION,
            ReportGenerationError.code,
        }
        assert expected_codes == set(_KINGSEC_STATUS_MAP.keys())

    def test_status_codes_are_valid_http(self) -> None:
        for code, status in _KINGSEC_STATUS_MAP.items():
            assert 100 <= status <= 599, f"Invalid status {status} for {code}"

    def test_report_generation_error_code_literal_matches_source(self) -> None:
        """_KINGSEC_STATUS_MAP hardcodes "KS-REPORT-001" as a literal, rather
        than importing ReportGenerationError (an adapter -> infrastructure
        import-linter violation). This guards against that literal silently
        drifting from the class it was copied from.
        """
        assert "KS-REPORT-001" == ReportGenerationError.code
        assert "KS-REPORT-001" in _KINGSEC_STATUS_MAP
