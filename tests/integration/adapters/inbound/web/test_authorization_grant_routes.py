"""HTTP-level tests for the Phase 4 authorization-grants route.

Real wired FastAPI app, real on-disk SQLite, real
require_admin/require_analyst dependencies - only get_current_user is
overridden, matching test_assessment_creation_submission_routes.py's own
precedent for HTTP-boundary auth tests.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.application.ports import TokenClaims
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Role
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


def _make_user(role: Role, user_id: str = "user-001") -> CurrentUser:
    now = datetime.now(UTC)
    return CurrentUser(
        user_id=user_id,
        username=f"{role.label.lower()}-user",
        role=role,
        claims=TokenClaims(
            user_id=user_id,
            username=f"{role.label.lower()}-user",
            role=role.label.lower(),
            token_type="access",
            jti="jti-test-phase4-routes",
            issued_at=now,
            expires_at=now,
        ),
    )


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    app = create_wired_application(log_stream=io.StringIO(), ensure_directories=False, validate_migrations=False)
    engine = create_database_engine(settings=app.settings)
    create_schema(engine)
    engine.dispose()
    return app


def _client_as(app: Application, role: Role | None, user_id: str = "user-001") -> TestClient:
    fastapi_app = create_fastapi_app(app)
    if role is not None:
        fastapi_app.dependency_overrides[get_current_user] = lambda: _make_user(role, user_id)
    return TestClient(fastapi_app, raise_server_exceptions=False)


_GRANT_BODY = {
    "authorized_by": "ciso@example.com",
    "authorizing_organization": "Example Corp",
    "target_specification_type": "ip_address",
    "target_specification_value": "10.0.0.5",
    "valid_from": "2026-01-01T00:00:00+00:00",
    "valid_until": "2099-01-01T00:00:00+00:00",
}


class TestCreateAuthorizationGrantRoute:
    def test_admin_can_create_a_grant(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ADMIN)
        resp = client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        assert resp.status_code == 201
        body = resp.json()
        assert body["grant_id"].startswith("agrt-")
        assert body["target_specification_value"] == "10.0.0.5"

    def test_analyst_cannot_create_a_grant(self, wired_app: Application) -> None:
        """The user's own rationale: an Analyst who could self-grant their
        own authorization would be able to authorize their own scans."""
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        assert resp.status_code == 403

    def test_viewer_cannot_create_a_grant(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.VIEWER)
        resp = client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        assert resp.status_code == 403

    def test_unauthenticated_request_is_refused(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=None)
        resp = client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        assert resp.status_code == 401

    def test_invalid_target_specification_type_is_a_validation_error(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ADMIN)
        bad_body = {**_GRANT_BODY, "target_specification_type": "not_a_real_type"}
        resp = client.post("/api/v1/authorization-grants", json=bad_body)
        assert resp.status_code == 400

    def test_create_publishes_authorization_grant_created_through_the_real_audit_route(
        self, wired_app: Application
    ) -> None:
        client = _client_as(wired_app, role=Role.ADMIN)
        create_resp = client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        assert create_resp.status_code == 201
        grant_id = create_resp.json()["grant_id"]

        audit_resp = client.get("/api/v1/audit", params={"action": "authorization_grant_created"})
        assert audit_resp.status_code == 200
        entries = audit_resp.json()["items"]
        assert any(e["resource_id"] == grant_id for e in entries)


class TestListAuthorizationGrantsRoute:
    def test_analyst_can_list_grants(self, wired_app: Application) -> None:
        admin_client = _client_as(wired_app, role=Role.ADMIN)
        create_resp = admin_client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        assert create_resp.status_code == 201

        analyst_client = _client_as(wired_app, role=Role.ANALYST)
        resp = analyst_client.get("/api/v1/authorization-grants")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert any(i["id"] == create_resp.json()["grant_id"] for i in items)

    def test_admin_can_list_grants_too(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ADMIN)
        resp = client.get("/api/v1/authorization-grants")
        assert resp.status_code == 200

    def test_viewer_cannot_list_grants(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.VIEWER)
        resp = client.get("/api/v1/authorization-grants")
        assert resp.status_code == 403


class TestRevokeAuthorizationGrantRoute:
    def test_admin_can_revoke_a_grant(self, wired_app: Application) -> None:
        admin_client = _client_as(wired_app, role=Role.ADMIN)
        create_resp = admin_client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        grant_id = create_resp.json()["grant_id"]

        revoke_resp = admin_client.delete(f"/api/v1/authorization-grants/{grant_id}")
        assert revoke_resp.status_code == 204

        # Revoked, no longer active - confirmed via the list route rather
        # than a get-by-id route (which does not exist), by checking the
        # revoked_at field is now populated.
        listed = admin_client.get("/api/v1/authorization-grants").json()["items"]
        row = next(i for i in listed if i["id"] == grant_id)
        assert row["revoked_at"] is not None

    def test_analyst_cannot_revoke_a_grant(self, wired_app: Application) -> None:
        admin_client = _client_as(wired_app, role=Role.ADMIN)
        create_resp = admin_client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        grant_id = create_resp.json()["grant_id"]

        analyst_client = _client_as(wired_app, role=Role.ANALYST)
        resp = analyst_client.delete(f"/api/v1/authorization-grants/{grant_id}")
        assert resp.status_code == 403

    def test_revoking_an_unknown_grant_is_404(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=Role.ADMIN)
        resp = client.delete("/api/v1/authorization-grants/agrt-does-not-exist")
        assert resp.status_code == 404

    def test_revoke_publishes_authorization_grant_revoked_through_the_real_audit_route(
        self, wired_app: Application
    ) -> None:
        client = _client_as(wired_app, role=Role.ADMIN)
        create_resp = client.post("/api/v1/authorization-grants", json=_GRANT_BODY)
        grant_id = create_resp.json()["grant_id"]

        revoke_resp = client.delete(f"/api/v1/authorization-grants/{grant_id}")
        assert revoke_resp.status_code == 204

        audit_resp = client.get("/api/v1/audit", params={"action": "authorization_grant_revoked"})
        assert audit_resp.status_code == 200
        entries = audit_resp.json()["items"]
        assert any(e["resource_id"] == grant_id for e in entries)


class TestCreatedGrantEnforcesAssessmentCreation:
    """End-to-end: a grant created through THIS route is genuinely usable
    by CreateAssessment's enforcement path - not just persisted, but
    actually a covering grant find_covering() would match."""

    def test_grant_created_via_the_route_covers_a_matching_assessment_creation(
        self, wired_app: Application
    ) -> None:
        admin_client = _client_as(wired_app, role=Role.ADMIN)
        grant_resp = admin_client.post(
            "/api/v1/authorization-grants",
            json={**_GRANT_BODY, "target_specification_value": "10.0.0.77"},
        )
        assert grant_resp.status_code == 201

        analyst_client = _client_as(wired_app, role=Role.ANALYST)
        assessment_resp = analyst_client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.77",
                "target_type": "ip_address",
                "authorized_by": "pentester@kingusecurity.com",
                "scope": "10.0.0.77",
                "profile_id": "quick-scan",
            },
        )
        assert assessment_resp.status_code == 201
