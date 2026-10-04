"""Tests for exception → HTTP status mapping."""

from __future__ import annotations

import pytest

import kingsec.adapters.inbound.web.error_handlers as error_handlers_module
from kingsec.adapters.inbound.web.error_handlers import (
    _KINGSEC_STATUS_MAP,
    _error_response,
    admin_operation_error,
    handle_assessment_not_found,
    handle_authorization_scope_error,
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
    AgentNotFoundError,
    AssessmentNotFoundError,
    AuthorizationScopeError,
    InputValidationError,
    PluginValidationError,
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
    async def test_authorization_scope_error_returns_403(self) -> None:
        exc = AuthorizationScopeError("10.0.0.5", "host_any_port")
        resp = await handle_authorization_scope_error(None, exc)
        assert resp.status_code == 403
        import json

        body = json.loads(resp.body)
        assert body["error_code"] == ErrorCode.AUTHORIZATION

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

    @pytest.mark.asyncio
    async def test_unhandled_exception_is_logged_server_side(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """KSEC-87-01: previously this global catch-all left zero
        server-side trace of what actually failed."""
        calls: list[str] = []

        class _RecordingLogger:
            def exception(self, msg: str, **_kwargs: object) -> None:
                calls.append(msg)

        monkeypatch.setattr(error_handlers_module, "_logger", _RecordingLogger())

        await handle_unhandled_exception(None, RuntimeError("db connection lost at /var/lib/kingsec.db"))

        assert len(calls) == 1


class TestAdminOperationError:
    """KSEC-87-01: agent_routes.py/backup_routes.py/plugin_routes.py had
    ~19 `except Exception as exc: raise HTTPException(..., detail=str(exc))`
    sites, broad enough to leak an unexpected internal exception's message
    even though the actually-expected failure in every case is one of this
    codebase's own deliberately-crafted, already-safe ApplicationError
    subclasses. These test the shared mechanism directly rather than
    duplicating near-identical assertions across all ~19 call sites -
    Section 5.3's own preferred test strategy."""

    def test_application_error_keeps_its_own_message(self) -> None:
        exc = AgentNotFoundError("Agent 'agent-1' not found")
        result = admin_operation_error(exc, "disable agent", status_code=404)
        assert result.status_code == 404
        assert result.detail == "Agent 'agent-1' not found"

    def test_a_different_application_error_subtype_also_keeps_its_message(self) -> None:
        """Not hardcoded to one error type - any ApplicationError subclass
        is treated as safe, matching Section 5.2's distinction between
        deliberately-crafted business/validation errors and genuinely
        unexpected ones."""
        exc = PluginValidationError("Missing manifest.json in plugin archive")
        result = admin_operation_error(exc, "install plugin", status_code=400)
        assert result.status_code == 400
        assert result.detail == "Missing manifest.json in plugin archive"

    def test_unexpected_exception_does_not_expose_its_message(self) -> None:
        exc = RuntimeError("sqlite database locked at /home/user/.kingsec/kingsec.db")
        result = admin_operation_error(exc, "create backup", status_code=400)
        assert "/home/user/.kingsec/kingsec.db" not in str(result.detail)
        assert "sqlite database locked" not in str(result.detail)

    def test_unexpected_exception_returns_500_regardless_of_the_requested_status(self) -> None:
        """The caller's status_code is only for the safe (ApplicationError)
        case - a genuinely unexpected failure is always a server error,
        never whatever status the specific route happened to request for
        its expected failure mode (e.g. 404 for "not found")."""
        exc = RuntimeError("unexpected")
        result = admin_operation_error(exc, "disable agent", status_code=404)
        assert result.status_code == 500

    def test_unexpected_exception_uses_the_same_generic_message_as_the_global_handler(self) -> None:
        exc = RuntimeError("internal failure detail")
        result = admin_operation_error(exc, "create backup", status_code=400)
        assert result.detail == KingSecError.default_user_message

    def test_unexpected_exception_is_logged_server_side_with_the_operation_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple] = []

        class _RecordingLogger:
            def exception(self, msg: str, **kwargs: object) -> None:
                calls.append((msg, kwargs))

        monkeypatch.setattr(error_handlers_module, "_logger", _RecordingLogger())

        admin_operation_error(RuntimeError("boom"), "install plugin", status_code=400)

        assert len(calls) == 1
        _msg, kwargs = calls[0]
        assert kwargs.get("operation") == "install plugin"

    def test_application_error_is_not_logged_as_unexpected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The safe, expected path should not also spam the logs as if it
        were an unexpected failure."""
        calls: list[str] = []

        class _RecordingLogger:
            def exception(self, msg: str, **_kwargs: object) -> None:
                calls.append(msg)

        monkeypatch.setattr(error_handlers_module, "_logger", _RecordingLogger())

        admin_operation_error(AgentNotFoundError("Agent 'x' not found"), "disable agent", status_code=404)

        assert calls == []


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
