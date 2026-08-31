"""Route-level regression tests for KSEC-64-04 max_length fixes on
schemas.py request bodies not already covered by a dedicated
integration test file: RefreshTokenBody, AssignRoleBody, and
ChangePasswordBody. (AdminResetPasswordBody is covered by
test_admin_reset_password_authorization.py.)

Same real-boundary pattern as test_rbac.py / test_worker_routes_authorization.py:
a real FastAPI app built from the actual routes.py router, backed by
real Login/RegisterUser/TokenService/ChangePassword/AssignRole wiring so
a genuine JWT is minted and verified through the real, unmocked
dependency chain - proving the max_length constraint is enforced at the
real HTTP boundary, not merely at the Pydantic-model level.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.ports import AuditPublisher, SessionRepository, TokenService
from kingsec.application.use_cases.assign_role import AssignRole
from kingsec.application.use_cases.change_password import ChangePassword
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.domain.audit import AuditEntry
from kingsec.domain.rate_limit import LockoutPolicy
from kingsec.domain.session import Session
from kingsec.infrastructure.config import Settings

from .test_rbac import (
    StubClock,
    StubHasher,
    StubLockoutRepo,
    StubMfaSecretRepo,
    StubRateLimiter,
    StubTokenService,
    StubUserRepo,
    _login,
    _register_user,
)


class _RecordingAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class _NoOpSessionRepo(SessionRepository):
    """No sessions are ever created in these schema-boundary tests -
    ChangePassword's KSEC-73-01 session revocation step just needs a
    real SessionRepository/RevokeAllSessions wiring to exist, not any
    actual sessions to revoke."""

    def save(self, session: Session) -> None:
        pass

    def find_by_id(self, session_id: str) -> Session | None:
        return None

    def find_by_jti(self, jti: str) -> Session | None:
        return None

    def find_by_refresh_jti(self, refresh_jti: str) -> Session | None:
        return None

    def find_active_by_user(self, user_id: str) -> list[Session]:
        return []

    def count_active_by_user(self, user_id: str) -> int:
        return 0

    def revoke(self, session_id: str) -> None:
        pass

    def revoke_all_by_user(self, user_id: str, exclude_session_id: str | None = None) -> None:
        pass

    def update_activity(self, session_id: str, last_activity: str) -> None:
        pass

    def update_refresh_jti(self, session_id: str, new_refresh_jti: str) -> None:
        pass

    def update_access_jti(self, session_id: str, new_jti: str) -> None:
        pass

    def delete_expired(self, before: str) -> int:
        return 0


def _build_app() -> tuple[FastAPI, StubUserRepo, _RecordingAuditPublisher]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    audit = _RecordingAuditPublisher()
    revoke_all_sessions = RevokeAllSessions(_NoOpSessionRepo(), token_service)

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            from kingsec.application.ports import PasswordHasher, ServiceAPI, UserRepository

            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == PasswordHasher:
                return hasher
            if service_type == AuditPublisher:
                return audit
            if service_type == RegisterUser:
                return RegisterUser(user_repo, hasher)
            if service_type == Login:
                return Login(
                    user_repo,
                    hasher,
                    token_service,
                    StubLockoutRepo(),
                    StubClock(),
                    LockoutPolicy(max_attempts=5, lockout_duration_seconds=900),
                    StubMfaSecretRepo(),
                )
            if service_type == RefreshToken:
                return RefreshToken(user_repo, token_service)
            if service_type == AuthorizationService:
                return AuthorizationService()
            if service_type == CheckRateLimit:
                return CheckRateLimit(StubRateLimiter())
            if service_type == ChangePassword:
                return ChangePassword(user_repo, hasher, revoke_all_sessions, audit)
            if service_type == AssignRole:
                return AssignRole(user_repo, revoke_all_sessions, audit)
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)

    return app, user_repo, audit


class TestRefreshTokenBodyMaxLengthBoundary:
    def test_over_limit_refresh_token_is_rejected_at_the_http_boundary(self) -> None:
        app, _ur, _audit = _build_app()
        client = TestClient(app)

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "x" * 1025})
        assert resp.status_code == 422, resp.text

    def test_real_refresh_token_still_succeeds(self) -> None:
        app, _ur, _audit = _build_app()
        client = TestClient(app)
        _register_user(client, username="admin1", email="admin1@example.com")

        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "SecurePass1"},
        )
        refresh_token = login_resp.json()["refresh_token"]

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 200, resp.text
        assert "access_token" in resp.json()


class TestAssignRoleBodyMaxLengthBoundary:
    def test_over_limit_role_is_rejected_at_the_http_boundary(self) -> None:
        app, user_repo, _audit = _build_app()
        client = TestClient(app)

        # First registered user is auto-promoted to Admin.
        _register_user(client, username="admin1", email="admin1@example.com")
        admin_token = _login(client, username="admin1")
        _register_user(client, username="target1", email="target1@example.com")
        target_id = user_repo.find_by_username("target1").id
        original_role = user_repo.find_by_id(target_id).role

        resp = client.put(
            f"/api/v1/users/{target_id}/role",
            json={"role": "x" * 21},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 422, resp.text

        # Downstream side effect did not occur: the target's role is unchanged.
        assert user_repo.find_by_id(target_id).role == original_role

    def test_real_role_assignment_still_succeeds(self) -> None:
        app, user_repo, _audit = _build_app()
        client = TestClient(app)

        _register_user(client, username="admin1", email="admin1@example.com")
        admin_token = _login(client, username="admin1")
        _register_user(client, username="target1", email="target1@example.com")
        target_id = user_repo.find_by_username("target1").id

        resp = client.put(
            f"/api/v1/users/{target_id}/role",
            json={"role": "analyst"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, resp.text
        assert user_repo.find_by_id(target_id).role.name.lower() == "analyst"


class TestChangePasswordBodyMaxLengthBoundary:
    def test_over_limit_current_password_is_rejected_at_the_http_boundary(self) -> None:
        app, user_repo, _audit = _build_app()
        client = TestClient(app)
        _register_user(client, username="user1", email="user1@example.com")
        token = _login(client, username="user1")
        original_hash = user_repo.find_by_username("user1").password_hash

        resp = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "x" * 129, "new_password": "NewSecurePass1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422, resp.text
        assert user_repo.find_by_username("user1").password_hash == original_hash

    def test_over_limit_new_password_is_rejected_at_the_http_boundary(self) -> None:
        app, user_repo, _audit = _build_app()
        client = TestClient(app)
        _register_user(client, username="user1", email="user1@example.com")
        token = _login(client, username="user1")
        original_hash = user_repo.find_by_username("user1").password_hash

        resp = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "SecurePass1", "new_password": "x" * 129},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422, resp.text
        assert user_repo.find_by_username("user1").password_hash == original_hash

    def test_real_password_change_still_succeeds(self) -> None:
        app, _ur, _audit = _build_app()
        client = TestClient(app)
        _register_user(client, username="user1", email="user1@example.com")
        token = _login(client, username="user1")

        resp = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "SecurePass1", "new_password": "NewSecurePass1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text

        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "user1", "password": "NewSecurePass1"},
        )
        assert login_resp.status_code == 200
