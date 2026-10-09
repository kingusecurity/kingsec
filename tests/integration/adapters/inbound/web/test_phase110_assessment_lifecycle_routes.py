"""KSEC-110: Phase 110 HTTP-level authorization matrix and cross-user
isolation verification for the complete Assessment lifecycle.

Every existing HTTP-level Assessment test (test_rbac.py, test_delete_
integration.py, etc.) uses a STUB ServiceAPI that raises
AssessmentNotFoundError unconditionally or returns fabricated data -
confirmed by source re-read - meaning none of them exercise the REAL
per-resource ownership check (check_assessment_access) against REAL
persisted, cross-user data. This file closes that gap: a real wired
FastAPI application, real on-disk SQLite, real authorization dependencies
(only get_current_user is overridden, never require_role/require_analyst/
require_viewer themselves).
"""

from __future__ import annotations

import io
import threading
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.application import SubmitAssessment
from kingsec.application.ports import ScannerPort, TokenClaims
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Role, Severity, Target
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()

_CREATE_BODY = {
    "target_value": "10.0.0.9",
    "target_type": "ip_address",
    "profile_id": "quick-scan",
    "authorized_by": "pentester@kingusecurity.com",
    "scope": "10.0.0.9",
}


class _CountingScanner(ScannerPort):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.invocation_count = 0

    def scan(self, target: Target):
        with self._lock:
            self.invocation_count += 1
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


def _use_test_scanner(app: Application, scanner: ScannerPort) -> None:
    app.container.register_instance(ScannerPort, scanner)
    submit = app.resolve(SubmitAssessment)
    submit._scanner = scanner
    submit._planner = None
    submit._scanner_executor = None


def _make_user(role: Role, user_id: str) -> CurrentUser:
    now = datetime.now(UTC)
    return CurrentUser(
        user_id=user_id,
        username=f"{role.label.lower()}-{user_id}",
        role=role,
        claims=TokenClaims(
            user_id=user_id,
            username=f"{role.label.lower()}-{user_id}",
            role=role.label.lower(),
            token_type="access",
            jti="jti-test-110",
            issued_at=now,
            expires_at=now,
        ),
    )


@pytest.fixture
def scanner_spy() -> _CountingScanner:
    return _CountingScanner()


@pytest.fixture
def wired_app(tmp_path, monkeypatch, scanner_spy: _CountingScanner) -> Application:
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    monkeypatch.setenv("KINGSEC_SECURITY__ENFORCE_AUTHORIZATION_SCOPE", "false")
    app = create_wired_application(log_stream=io.StringIO(), ensure_directories=False, validate_migrations=False)
    engine = create_database_engine(settings=app.settings)
    create_schema(engine)
    engine.dispose()
    _use_test_scanner(app, scanner_spy)
    return app


def _client_as(app: Application, role: Role | None, user_id: str = "user-1") -> TestClient:
    fastapi_app = create_fastapi_app(app)
    if role is not None:
        fastapi_app.dependency_overrides[get_current_user] = lambda: _make_user(role, user_id)
    return TestClient(fastapi_app, raise_server_exceptions=False)


def _create_owned_assessment(wired_app: Application, owner_id: str = "owner-user") -> str:
    owner_client = _client_as(wired_app, role=Role.ANALYST, user_id=owner_id)
    resp = owner_client.post("/api/v1/assessments", json=_CREATE_BODY)
    assert resp.status_code == 201
    return resp.json()["assessment_id"]


_NONEXISTENT_ID = "asmt-00000000000000000000000000000000"


# ── D/E: authorization matrix + cross-user isolation ─────────────────────


class TestAuthorizationMatrixExistingAssessment:
    """Every operation, against a REAL, existing, owned Assessment, from
    every role/identity combination."""

    @pytest.mark.parametrize(
        "role,user_id,expected_statuses",
        [
            (None, "n/a", (401, 403)),
            (Role.VIEWER, "attacker", (404,)),
            (Role.ANALYST, "attacker", (404,)),
            (Role.ADMIN, "admin-1", (200,)),
            (Role.VIEWER, "owner-user", (200,)),
        ],
    )
    def test_get_assessment(self, wired_app: Application, role, user_id, expected_statuses) -> None:
        assessment_id = _create_owned_assessment(wired_app, owner_id="owner-user")
        client = _client_as(wired_app, role=role, user_id=user_id)
        resp = client.get(f"/api/v1/assessments/{assessment_id}")
        assert resp.status_code in expected_statuses, f"got {resp.status_code}: {resp.text}"
        if resp.status_code == 404:
            # No information disclosure: a 404 for a real, existing id
            # must look identical to a 404 for a nonexistent one.
            other = client.get(f"/api/v1/assessments/{_NONEXISTENT_ID}")
            assert other.status_code == 404
            assert resp.json().keys() == other.json().keys()

    @pytest.mark.parametrize(
        "role,user_id,expected_statuses",
        [
            (None, "n/a", (401, 403)),
            (Role.VIEWER, "owner-user", (403,)),  # viewer role gate blocks before ownership is even checked
            (Role.ANALYST, "attacker", (404,)),
            (Role.ADMIN, "admin-1", (202,)),
            (Role.ANALYST, "owner-user", (202,)),
        ],
    )
    def test_start_assessment(self, wired_app: Application, role, user_id, expected_statuses) -> None:
        assessment_id = _create_owned_assessment(wired_app, owner_id="owner-user")
        client = _client_as(wired_app, role=role, user_id=user_id)
        resp = client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert resp.status_code in expected_statuses, f"got {resp.status_code}: {resp.text}"

    @pytest.mark.parametrize(
        "role,user_id,expected_statuses",
        [
            (None, "n/a", (401, 403)),
            (Role.VIEWER, "owner-user", (403,)),
            (Role.ANALYST, "attacker", (404,)),
            (Role.ADMIN, "admin-1", (200,)),
        ],
    )
    def test_cancel_assessment(self, wired_app: Application, role, user_id, expected_statuses) -> None:
        assessment_id = _create_owned_assessment(wired_app, owner_id="owner-user")
        client = _client_as(wired_app, role=role, user_id=user_id)
        resp = client.post(f"/api/v1/assessments/{assessment_id}/cancel")
        assert resp.status_code in expected_statuses, f"got {resp.status_code}: {resp.text}"

    @pytest.mark.parametrize(
        "role,user_id,expected_statuses",
        [
            (None, "n/a", (401, 403)),
            (Role.VIEWER, "owner-user", (403,)),
            (Role.ANALYST, "attacker", (404,)),
        ],
    )
    def test_delete_assessment_denied_cases(self, wired_app: Application, role, user_id, expected_statuses) -> None:
        assessment_id = _create_owned_assessment(wired_app, owner_id="owner-user")
        client = _client_as(wired_app, role=role, user_id=user_id)
        resp = client.delete(f"/api/v1/assessments/{assessment_id}")
        assert resp.status_code in expected_statuses, f"got {resp.status_code}: {resp.text}"
        # Confirm no side effect: the assessment must still exist.
        owner_client = _client_as(wired_app, role=Role.ANALYST, user_id="owner-user")
        confirm = owner_client.get(f"/api/v1/assessments/{assessment_id}")
        assert confirm.status_code == 200

    def test_owner_can_delete_own_assessment(self, wired_app: Application) -> None:
        assessment_id = _create_owned_assessment(wired_app, owner_id="owner-user")
        owner_client = _client_as(wired_app, role=Role.ANALYST, user_id="owner-user")
        resp = owner_client.delete(f"/api/v1/assessments/{assessment_id}")
        assert resp.status_code == 204
        confirm = owner_client.get(f"/api/v1/assessments/{assessment_id}")
        assert confirm.status_code == 404

    def test_admin_can_delete_any_assessment(self, wired_app: Application) -> None:
        assessment_id = _create_owned_assessment(wired_app, owner_id="owner-user")
        admin_client = _client_as(wired_app, role=Role.ADMIN, user_id="admin-1")
        resp = admin_client.delete(f"/api/v1/assessments/{assessment_id}")
        assert resp.status_code == 204


class TestAuthorizationMatrixNonexistentAssessment:
    """Same operations against an id that never existed - must behave
    identically to a cross-user 404 (no information disclosure about
    existence)."""

    @pytest.mark.parametrize("role,user_id", [(Role.VIEWER, "someone"), (Role.ANALYST, "someone"), (Role.ADMIN, "admin-1")])
    def test_get_nonexistent_returns_404_for_every_authenticated_role(
        self, wired_app: Application, role, user_id
    ) -> None:
        client = _client_as(wired_app, role=role, user_id=user_id)
        resp = client.get(f"/api/v1/assessments/{_NONEXISTENT_ID}")
        assert resp.status_code == 404

    def test_delete_nonexistent_returns_404_even_for_admin(self, wired_app: Application) -> None:
        admin_client = _client_as(wired_app, role=Role.ADMIN, user_id="admin-1")
        resp = admin_client.delete(f"/api/v1/assessments/{_NONEXISTENT_ID}")
        assert resp.status_code == 404


class TestCrossUserIsolation:
    def test_attacker_cannot_read_start_cancel_or_delete_victim_assessment(
        self, wired_app: Application, scanner_spy: _CountingScanner
    ) -> None:
        victim_id = _create_owned_assessment(wired_app, owner_id="victim")
        attacker = _client_as(wired_app, role=Role.ANALYST, user_id="attacker")

        get_resp = attacker.get(f"/api/v1/assessments/{victim_id}")
        start_resp = attacker.post(f"/api/v1/assessments/{victim_id}/start")
        cancel_resp = attacker.post(f"/api/v1/assessments/{victim_id}/cancel")
        delete_resp = attacker.delete(f"/api/v1/assessments/{victim_id}")

        for resp in (get_resp, start_resp, cancel_resp, delete_resp):
            assert resp.status_code == 404, f"{resp.request.method} {resp.request.url}: {resp.status_code}"

        # No side effect at all: the victim's assessment is untouched and
        # the scanner was never invoked.
        assert scanner_spy.invocation_count == 0
        victim_client = _client_as(wired_app, role=Role.ANALYST, user_id="victim")
        confirm = victim_client.get(f"/api/v1/assessments/{victim_id}")
        assert confirm.status_code == 200
        assert confirm.json()["status"] == "authorized"

    def test_list_assessments_never_returns_another_users_assessment(self, wired_app: Application) -> None:
        _create_owned_assessment(wired_app, owner_id="user-a")
        _create_owned_assessment(wired_app, owner_id="user-b")

        client_a = _client_as(wired_app, role=Role.ANALYST, user_id="user-a")
        resp = client_a.get("/api/v1/assessments")
        assert resp.status_code == 200
        owner_ids = {item.get("owner_id") for item in resp.json()["items"] if "owner_id" in item}
        assert "user-b" not in owner_ids

    def test_admin_list_sees_all_assessments(self, wired_app: Application) -> None:
        _create_owned_assessment(wired_app, owner_id="user-a")
        _create_owned_assessment(wired_app, owner_id="user-b")

        admin_client = _client_as(wired_app, role=Role.ADMIN, user_id="admin-1")
        resp = admin_client.get("/api/v1/assessments")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 2


# ── M: HTTP boundary verification - malformed/unexpected request shapes ──


class TestHttpBoundaryFuzzing:
    def test_malformed_json_body_returns_422_not_500(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post(
            "/api/v1/assessments",
            content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_required_fields_returns_422_not_500(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post("/api/v1/assessments", json={"target_value": "10.0.0.9"})
        assert resp.status_code == 422

    def test_unknown_extra_field_is_rejected_not_silently_ignored(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post("/api/v1/assessments", json={**_CREATE_BODY, "unexpected_field": "value"})
        assert resp.status_code == 422

    def test_wrong_field_type_returns_422_not_500(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post("/api/v1/assessments", json={**_CREATE_BODY, "target_value": 12345})
        assert resp.status_code == 422

    def test_extremely_large_target_value_returns_422_not_500(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post("/api/v1/assessments", json={**_CREATE_BODY, "target_value": "x" * 100_000})
        assert resp.status_code in (400, 422)

    def test_invalid_assessment_id_shapes_never_500_on_get(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        for bad_id in ("", " ", "../../etc/passwd", "'; DROP TABLE assessments; --", "x" * 5000):
            resp = client.get(f"/api/v1/assessments/{bad_id}")
            assert resp.status_code < 500, f"id={bad_id!r} got {resp.status_code}"

    def test_nested_object_instead_of_string_returns_422_not_500(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post("/api/v1/assessments", json={**_CREATE_BODY, "target_value": {"nested": "object"}})
        assert resp.status_code == 422
