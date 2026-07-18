"""Global exception handling: comprehensive tests."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from freezegun import freeze_time

from kingsec.interfaces.api.models import ApiError


class TestApiErrorModel:
    def test_required_fields(self) -> None:
        error = ApiError(
            timestamp=datetime.now(timezone.utc),
            request_id="123e4567-e89b-12d3-a456-426614174000",
            status=422,
            error="TEST_ERROR",
            message="Something went wrong",
            path="/test",
        )
        assert error.timestamp is not None
        assert error.request_id == "123e4567-e89b-12d3-a456-426614174000"
        assert error.status == 422
        assert error.error == "TEST_ERROR"
        assert error.message == "Something went wrong"
        assert error.path == "/test"
        assert error.details is None

    def test_details_optional(self) -> None:
        error = ApiError(
            timestamp=datetime.now(timezone.utc),
            request_id="123e4567-e89b-12d3-a456-426614174000",
            status=500,
            error="INTERNAL_ERROR",
            message="Oops",
            path="/fail",
            details={"key": "value"},
        )
        assert error.details == {"key": "value"}

    def test_serializes_to_json(self) -> None:
        error = ApiError(
            timestamp=datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc),
            request_id="123e4567-e89b-12d3-a456-426614174000",
            status=422,
            error="VALIDATION_ERROR",
            message="Bad input",
            path="/test",
        )
        data = error.model_dump(mode="json")
        assert data["timestamp"] == "2026-07-18T12:00:00Z"
        assert data["status"] == 422
        assert data["error"] == "VALIDATION_ERROR"


class _ErrorTestBase:
    """Base for tests that raise exceptions through the error handlers."""

    def _build_app(self):
        from fastapi import FastAPI

        app = FastAPI()
        from kingsec.interfaces.api.errors import register_error_handlers

        register_error_handlers(app)
        return app

    def _make_client(self, app):
        return TestClient(app, raise_server_exceptions=False)


class TestErrorResponseFormat(_ErrorTestBase):
    """Every error response must conform to the ApiError schema."""

    def setup_method(self) -> None:
        app = self._build_app()

        @app.get("/raise/value-error")
        async def _raise_value_error() -> None:
            raise ValueError("Invalid input value")

        @app.get("/raise/key-error")
        async def _raise_key_error() -> None:
            raise KeyError("missing_key")

        @app.get("/raise/permission")
        async def _raise_permission() -> None:
            raise PermissionError("Access denied")

        @app.get("/raise/not-found")
        async def _raise_file_not_found() -> None:
            raise FileNotFoundError("file.txt not found")

        @app.get("/raise/timeout")
        async def _raise_timeout() -> None:
            raise TimeoutError("Operation timed out")

        @app.get("/raise/not-implemented")
        async def _raise_not_implemented() -> None:
            raise NotImplementedError("Feature not implemented")

        self.client = self._make_client(app)

    def _assert_error_schema(self, response, expected_status: int, expected_error: str) -> dict:
        assert response.status_code == expected_status
        assert response.headers["content-type"] == "application/json"
        body = response.json()
        assert "timestamp" in body
        assert "request_id" in body
        assert "status" in body
        assert "error" in body
        assert "message" in body
        assert "path" in body
        assert body["status"] == expected_status
        assert body["error"] == expected_error
        assert len(body["request_id"]) == 36
        assert re.match(r"^[0-9a-f-]{36}$", body["request_id"])
        assert isinstance(body["message"], str)
        assert isinstance(body["path"], str)
        assert body["path"].startswith("/")
        return body

    def test_value_error_returns_422(self) -> None:
        response = self.client.get("/raise/value-error")
        self._assert_error_schema(response, 422, "VALIDATION_ERROR")

    def test_key_error_returns_404(self) -> None:
        response = self.client.get("/raise/key-error")
        self._assert_error_schema(response, 404, "NOT_FOUND")

    def test_permission_error_returns_403(self) -> None:
        response = self.client.get("/raise/permission")
        self._assert_error_schema(response, 403, "FORBIDDEN")

    def test_file_not_found_returns_404(self) -> None:
        response = self.client.get("/raise/not-found")
        self._assert_error_schema(response, 404, "NOT_FOUND")

    def test_timeout_error_returns_504(self) -> None:
        response = self.client.get("/raise/timeout")
        self._assert_error_schema(response, 504, "TIMEOUT_ERROR")

    def test_not_implemented_error_returns_500(self) -> None:
        response = self.client.get("/raise/not-implemented")
        self._assert_error_schema(response, 500, "NOT_IMPLEMENTED")


class TestDomainErrorHandling(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        from kingsec.domain.errors import DomainError, IllegalStateTransition, InvariantViolation

        @app.get("/raise/invariant")
        async def _raise_invariant() -> None:
            raise InvariantViolation("Invalid state")

        @app.get("/raise/illegal-state")
        async def _raise_illegal_state() -> None:
            raise IllegalStateTransition("Cannot transition")

        @app.get("/raise/domain")
        async def _raise_domain() -> None:
            raise DomainError("Generic domain error")

        self.client = self._make_client(app)

    def test_invariant_violation_returns_422(self) -> None:
        response = self.client.get("/raise/invariant")
        assert response.status_code == 422
        assert response.json()["error"] == "VALIDATION_ERROR"

    def test_illegal_state_transition_returns_409(self) -> None:
        response = self.client.get("/raise/illegal-state")
        assert response.status_code == 409
        assert response.json()["error"] == "CONFLICT"

    def test_domain_error_returns_500(self) -> None:
        response = self.client.get("/raise/domain")
        assert response.status_code == 500
        assert response.json()["error"] == "DOMAIN_ERROR"


class TestApplicationErrorHandling(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        from kingsec.application.errors import (
            ApplicationError,
            AssessmentNotFoundError,
            InputValidationError,
            ReportNotFoundError,
            ScannerDuplicateError,
            ScannerPluginError,
            ScannerTimeoutError,
            ScannerUnavailableError,
        )

        @app.get("/raise/input-validation")
        async def _raise_input_validation() -> None:
            raise InputValidationError("Invalid request body")

        @app.get("/raise/scanner-plugin")
        async def _raise_scanner_plugin() -> None:
            raise ScannerPluginError("Scanner plugin crashed")

        @app.get("/raise/scanner-duplicate")
        async def _raise_scanner_duplicate() -> None:
            raise ScannerDuplicateError("Scanner already registered")

        @app.get("/raise/scanner-unavailable")
        async def _raise_scanner_unavailable() -> None:
            raise ScannerUnavailableError("Scanner offline")

        @app.get("/raise/scanner-timeout")
        async def _raise_scanner_timeout() -> None:
            raise ScannerTimeoutError("Scanner timed out")

        @app.get("/raise/application")
        async def _raise_application() -> None:
            raise ApplicationError("Generic application error")

        @app.get("/raise/assessment-not-found")
        async def _raise_assessment_not_found() -> None:
            raise AssessmentNotFoundError("Assessment 42 not found")

        @app.get("/raise/report-not-found")
        async def _raise_report_not_found() -> None:
            raise ReportNotFoundError("Report 42 not found")

        self.client = self._make_client(app)

    def test_input_validation_returns_422(self) -> None:
        response = self.client.get("/raise/input-validation")
        assert response.status_code == 422
        assert response.json()["error"] == "VALIDATION_ERROR"
        assert "Invalid request body" in response.json()["message"]

    def test_scanner_plugin_error_returns_500(self) -> None:
        response = self.client.get("/raise/scanner-plugin")
        assert response.status_code == 500
        assert response.json()["error"] == "SCANNER_ERROR"

    def test_scanner_duplicate_returns_409(self) -> None:
        response = self.client.get("/raise/scanner-duplicate")
        assert response.status_code == 409
        assert response.json()["error"] == "CONFLICT"

    def test_scanner_unavailable_returns_503(self) -> None:
        response = self.client.get("/raise/scanner-unavailable")
        assert response.status_code == 503
        assert response.json()["error"] == "SERVICE_UNAVAILABLE"

    def test_scanner_timeout_returns_504(self) -> None:
        response = self.client.get("/raise/scanner-timeout")
        assert response.status_code == 504
        assert response.json()["error"] == "SCANNER_TIMEOUT"

    def test_application_error_returns_500(self) -> None:
        response = self.client.get("/raise/application")
        assert response.status_code == 500
        assert response.json()["error"] == "APPLICATION_ERROR"

    def test_assessment_not_found_returns_404(self) -> None:
        response = self.client.get("/raise/assessment-not-found")
        assert response.status_code == 404
        assert response.json()["error"] == "NOT_FOUND"

    def test_report_not_found_returns_404(self) -> None:
        response = self.client.get("/raise/report-not-found")
        assert response.status_code == 404
        assert response.json()["error"] == "NOT_FOUND"


class TestSharedErrorHandling(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        from kingsec.shared.errors import AuthorizationError, ResourceNotFoundError, ValidationError

        @app.get("/raise/shared-validation")
        async def _raise_validation() -> None:
            raise ValidationError("Invalid shared value")

        @app.get("/raise/resource-not-found")
        async def _raise_resource_not_found() -> None:
            raise ResourceNotFoundError("Resource missing")

        @app.get("/raise/authorization")
        async def _raise_authorization() -> None:
            raise AuthorizationError("Not authorized")

        self.client = self._make_client(app)

    def test_validation_error_returns_422(self) -> None:
        response = self.client.get("/raise/shared-validation")
        assert response.status_code == 422
        assert response.json()["error"] == "VALIDATION_ERROR"

    def test_resource_not_found_returns_404(self) -> None:
        response = self.client.get("/raise/resource-not-found")
        assert response.status_code == 404
        assert response.json()["error"] == "NOT_FOUND"

    def test_authorization_error_returns_403(self) -> None:
        response = self.client.get("/raise/authorization")
        assert response.status_code == 403
        assert response.json()["error"] == "FORBIDDEN"


class TestRequestId(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        @app.get("/raise")
        async def _raise() -> None:
            raise ValueError("test")

        self.client = self._make_client(app)

    def test_request_id_is_unique_per_request(self) -> None:
        response1 = self.client.get("/raise")
        response2 = self.client.get("/raise")
        rid1 = response1.json()["request_id"]
        rid2 = response2.json()["request_id"]
        assert rid1 != rid2

    def test_request_id_is_valid_uuid4(self) -> None:
        response = self.client.get("/raise")
        request_id = response.json()["request_id"]
        parsed = uuid.UUID(request_id, version=4)
        assert parsed.version == 4


class TestTimestamp(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        @app.get("/raise")
        async def _raise() -> None:
            raise ValueError("test")

        self.client = self._make_client(app)

    def test_timestamp_is_present(self) -> None:
        response = self.client.get("/raise")
        assert "timestamp" in response.json()

    def test_timestamp_is_valid_iso8601(self) -> None:
        response = self.client.get("/raise")
        timestamp = response.json()["timestamp"]
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    @freeze_time("2026-07-18T12:30:00Z")
    def test_timestamp_reflects_current_time(self) -> None:
        response = self.client.get("/raise")
        assert response.json()["timestamp"] == "2026-07-18T12:30:00Z"


class TestPath(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        @app.get("/custom/path/here")
        async def _raise() -> None:
            raise ValueError("test")

        self.client = self._make_client(app)

    def test_path_matches_request_url(self) -> None:
        response = self.client.get("/custom/path/here")
        assert response.json()["path"] == "/custom/path/here"


class TestUnhandledException(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        @app.get("/raise")
        async def _raise() -> None:
            raise RuntimeError("Something unexpected happened")

        self.client = self._make_client(app)

    def test_unhandled_returns_500(self) -> None:
        response = self.client.get("/raise")
        assert response.status_code == 500

    def test_unhandled_returns_generic_message(self) -> None:
        response = self.client.get("/raise")
        data = response.json()
        assert data["error"] == "INTERNAL_ERROR"
        assert "unexpected error" in data["message"].lower()
        assert "try again" in data["message"].lower()

    def test_unhandled_does_not_leak_stack_trace(self) -> None:
        response = self.client.get("/raise")
        data = response.json()
        assert "Traceback" not in data["message"]
        assert "RuntimeError" not in data["message"]

    def test_unhandled_returns_standard_json(self) -> None:
        response = self.client.get("/raise")
        assert response.headers["content-type"] == "application/json"


class Test404Errors(_ErrorTestBase):
    def setup_method(self) -> None:
        app = self._build_app()

        @app.get("/existing")
        async def _existing() -> dict:
            return {"ok": True}

        self.client = self._make_client(app)

    def test_not_found_returns_404(self) -> None:
        response = self.client.get("/nonexistent-route")
        assert response.status_code == 404

    def test_not_found_error_body(self) -> None:
        response = self.client.get("/nonexistent-route")
        body = response.json()
        assert body["status"] == 404
        assert body["path"] == "/nonexistent-route"
        assert body["error"] == "HTTP_ERROR"

    def test_not_found_is_json(self) -> None:
        response = self.client.get("/nonexistent-route")
        assert response.headers["content-type"] == "application/json"

    def test_method_not_allowed_returns_405(self) -> None:
        response = self.client.post("/existing")
        assert response.status_code == 405

    def test_method_not_allowed_is_json(self) -> None:
        response = self.client.post("/existing")
        assert response.headers["content-type"] == "application/json"

    def test_method_not_allowed_error_body(self) -> None:
        response = self.client.post("/existing")
        body = response.json()
        assert body["status"] == 405
        assert body["path"] == "/existing"


class TestErrorResponseWithApp:
    """Validate errors using the real create_app."""

    def setup_method(self) -> None:
        from kingsec.interfaces.api.app import create_app

        self.client = TestClient(create_app(), raise_server_exceptions=False)

    def test_404_from_real_app(self) -> None:
        response = self.client.get("/api/nonexistent")
        assert response.status_code == 404
        body = response.json()
        assert body["status"] == 404
        assert body["error"] == "HTTP_ERROR"
        assert "timestamp" in body
        assert "request_id" in body
        assert "path" in body
