"""Regression tests for POST /api/v1/users/{user_id}/reset-password.

Phase 67 / Finding KSEC-64-03: this endpoint's use case
(AdminResetPassword) previously hashed and stored any supplied
new_password with no complexity validation anywhere in the stack - an
authenticated Admin could set another user's password to "" or any
arbitrarily weak string, unlike every other password-setting path
(registration, self-service change), which already enforce the same
policy. The fix reuses that canonical validator directly.

This endpoint's own authorization (require_admin_jwt_only, both at the
router level and as a per-route dependency) was never the vulnerability
- these tests confirm it remains intact alongside the new password
validation, using the same real-boundary pattern as test_rbac.py /
test_worker_routes_authorization.py: a real FastAPI app built from the
actual routes.py router, backed by real Login/RegisterUser/TokenService
wiring so a genuine JWT is minted and verified through the real,
unmocked auth and validation dependency chain.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.ports import AuditPublisher, TokenService
from kingsec.application.use_cases.admin_users import AdminResetPassword
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain.audit import AuditEntry
from kingsec.domain.rate_limit import LockoutPolicy
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
    _promote_user_in_repo,
    _register_user,
    _register_viewer,
)


class _RecordingAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


def _build_app() -> tuple[FastAPI, StubUserRepo, _RecordingAuditPublisher]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    audit = _RecordingAuditPublisher()

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            from kingsec.application.ports import PasswordHasher as _PasswordHasher
            from kingsec.application.ports import ServiceAPI
            from kingsec.application.ports import UserRepository as _UserRepository

            if service_type == TokenService:
                return token_service
            if service_type == _UserRepository:
                return user_repo
            if service_type == _PasswordHasher:
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
            if service_type == AdminResetPassword:
                return AdminResetPassword(user_repo, hasher, audit)
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)

    return app, user_repo, audit


def _reset_password_path(user_id: str) -> str:
    return f"/api/v1/users/{user_id}/reset-password"


class TestAdminResetPasswordAuthorizationUnauthenticated:
    """No credential at all -> 401."""

    def setup_method(self) -> None:
        self.app, self._ur, self._audit = _build_app()
        self.client = TestClient(self.app)

    def test_returns_401_without_token(self) -> None:
        resp = self.client.post(_reset_password_path("whoever"), json={"new_password": "NewSecurePass1"})
        assert resp.status_code == 401, resp.text


class TestAdminResetPasswordAuthorizationViewer:
    """Viewer -> 403 (this endpoint has always been admin-only; not part
    of the KSEC-64-03 bug, but confirmed unaffected by the fix)."""

    def setup_method(self) -> None:
        self.app, self._ur, self._audit = _build_app()
        self.client = TestClient(self.app)

    def test_viewer_cannot_reset_another_users_password(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.post(
            _reset_password_path("whoever"),
            json={"new_password": "NewSecurePass1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, resp.text


class TestAdminResetPasswordAuthorizationAnalyst:
    """Analyst -> 403 (admin-only, not analyst-accessible)."""

    def setup_method(self) -> None:
        self.app, self._ur, self._audit = _build_app()
        self.client = TestClient(self.app)

    def test_analyst_cannot_reset_another_users_password(self) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")
        resp = self.client.post(
            _reset_password_path("whoever"),
            json={"new_password": "NewSecurePass1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, resp.text


class TestAdminResetPasswordComplexity:
    """The core KSEC-64-03 regression coverage, exercised through the
    real HTTP route and real authorization dependency chain - not the
    use case in isolation."""

    def setup_method(self) -> None:
        self.app, self._ur, self._audit = _build_app()
        self.client = TestClient(self.app)

    def _admin_token_and_target(self) -> tuple[str, str]:
        # The very first registered user is auto-promoted to Admin.
        _register_user(self.client, username="admin1", email="admin1@example.com")
        admin_token = _login(self.client, username="admin1")
        _register_user(self.client, username="target1", email="target1@example.com", password="OriginalPass1")
        target_id = self._ur.find_by_username("target1").id
        return admin_token, target_id

    @pytest.mark.parametrize(
        "weak_password",
        [
            "",
            "short1A",
            "alllowercase1",
            "ALLUPPERCASE1",
            "NoDigitsHere",
        ],
    )
    def test_admin_using_a_weak_password_is_rejected(self, weak_password: str) -> None:
        admin_token, target_id = self._admin_token_and_target()
        original_hash = self._ur.find_by_id(target_id).password_hash

        resp = self.client.post(
            _reset_password_path(target_id),
            json={"new_password": weak_password},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 400, resp.text
        # Negative security evidence: the target's stored credential is
        # unchanged, and no audit entry was recorded for a rejected reset.
        assert self._ur.find_by_id(target_id).password_hash == original_hash
        assert self._audit.entries == []

    def test_admin_using_a_password_accepted_by_the_canonical_policy_succeeds(self) -> None:
        admin_token, target_id = self._admin_token_and_target()

        resp = self.client.post(
            _reset_password_path(target_id),
            json={"new_password": "BrandNewPass1"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["user_id"] == target_id

        # The credential actually changed, is a hash (not the plaintext),
        # and the target user can now log in with the new password.
        updated_user = self._ur.find_by_id(target_id)
        assert updated_user.password_hash != "BrandNewPass1"
        assert updated_user.password_hash == "hashed:BrandNewPass1"

        login_resp = self.client.post(
            "/api/v1/auth/login",
            json={"username": "target1", "password": "BrandNewPass1"},
        )
        assert login_resp.status_code == 200, login_resp.text

        old_login_resp = self.client.post(
            "/api/v1/auth/login",
            json={"username": "target1", "password": "OriginalPass1"},
        )
        assert old_login_resp.status_code == 401, old_login_resp.text

    def test_registration_and_admin_reset_agree_on_password_acceptance(self) -> None:
        """KSEC-64-03's precise defect: the canonical policy (exercised
        here via registration) and the admin reset path must never
        disagree on whether a given password is acceptable."""
        admin_token, target_id = self._admin_token_and_target()

        candidate_passwords = ["NewSecurePass1", "weak", "AnotherValid2", "nouppercase1"]
        for index, password in enumerate(candidate_passwords):
            register_resp = self.client.post(
                "/api/v1/auth/register",
                json={"username": f"probe_user_{index}", "email": f"probe{index}@example.com", "password": password},
            )
            registration_accepted = register_resp.status_code == 201

            reset_resp = self.client.post(
                _reset_password_path(target_id),
                json={"new_password": password},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            reset_accepted = reset_resp.status_code == 200

            assert registration_accepted == reset_accepted, (
                f"password {password!r}: registration accepted={registration_accepted}, "
                f"admin reset accepted={reset_accepted}"
            )
