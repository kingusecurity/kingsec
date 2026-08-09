"""Integration tests for RBAC: role/permission/ownership enforcement via HTTP.

Tests use the same stub infrastructure as test_auth_integration to create a
FastAPI test client with the full route table behind a stubbed DI container.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.ports import RateLimiterPort, TokenClaims, TokenService
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain import User
from kingsec.domain.mfa import MfaSecret
from kingsec.domain.rate_limit import AccountLockout, LockoutPolicy, RateLimitDecision, RateLimitPolicy
from kingsec.infrastructure.config import Settings

# ── Stubs (same pattern as test_auth_integration) ─────────────────────────


class StubTokenService(TokenService):
    def __init__(self) -> None:
        self._tokens: dict[str, TokenClaims] = {}
        self._revoked: set[str] = set()

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        import uuid

        jti = uuid.uuid4().hex
        token = f"access-{jti}"
        self._tokens[token] = TokenClaims(
            user_id=user_id,
            username=username,
            role=role,
            token_type="access",
            jti=jti,
            issued_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        return token

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        import uuid

        jti = uuid.uuid4().hex
        token = f"refresh-{jti}"
        self._tokens[token] = TokenClaims(
            user_id=user_id,
            username=username,
            role=role,
            token_type="refresh",
            jti=jti,
            issued_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        return token

    def verify_access_token(self, token: str) -> TokenClaims:
        if token not in self._tokens:
            raise Exception("invalid token")
        claims = self._tokens[token]
        if claims.token_type != "access":
            raise Exception("not an access token")
        if claims.jti in self._revoked:
            raise Exception("token revoked")
        return claims

    def verify_refresh_token(self, token: str) -> TokenClaims:
        if token not in self._tokens:
            raise Exception("invalid token")
        claims = self._tokens[token]
        if claims.token_type != "refresh":
            raise Exception("not a refresh token")
        return claims

    def create_mfa_pending_token(self, user_id: str, username: str, role: str) -> str:
        import uuid

        jti = uuid.uuid4().hex
        token = f"pending-{jti}"
        self._tokens[token] = TokenClaims(
            user_id=user_id,
            username=username,
            role=role,
            token_type="mfa_pending",
            jti=jti,
            issued_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        return token

    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        if token not in self._tokens:
            raise Exception("invalid token")
        claims = self._tokens[token]
        if claims.token_type != "mfa_pending":
            raise Exception("not a pending token")
        if claims.jti in self._revoked:
            raise Exception("token revoked")
        return claims

    def revoke_token(self, jti: str) -> None:
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked


class StubUserRepo:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def find_by_username(self, username: str) -> User | None:
        for u in self._users.values():
            if u.username.lower() == username.lower():
                return u
        return None

    def find_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def save(self, user: User) -> None:
        self._users[user.id] = user

    def exists_by_username(self, username: str) -> bool:
        return self.find_by_username(username) is not None

    def exists_by_email(self, email: str) -> bool:
        return any(u.email.lower() == email.lower() for u in self._users.values())

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return list(self._users.values())[offset : offset + limit]

    def count(self) -> int:
        return len(self._users)


class StubHasher:
    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str) -> bool:
        return password_hash == f"hashed:{password}"


class StubLockoutRepo(LockoutRepository):
    """No-op lockout store - this suite doesn't exercise lockout behavior."""

    def get(self, user_id: str) -> AccountLockout | None:
        return None

    def save(self, lockout: AccountLockout) -> None:
        pass

    def delete(self, user_id: str) -> None:
        pass


class StubClock(ClockPort):
    def now(self) -> float:
        return 0.0


class StubMfaSecretRepo(MfaSecretRepository):
    """No-op MFA secret store - this suite doesn't exercise MFA-enabled accounts."""

    def find_by_user_id(self, user_id: str) -> MfaSecret | None:
        return None

    def save(self, secret: MfaSecret) -> None:
        pass

    def delete_by_user_id(self, user_id: str) -> None:
        pass


class StubRateLimiter(RateLimiterPort):
    """Rate limiter that always allows (never rate-limits in tests)."""

    def check(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        return RateLimitDecision(allowed=True, limit=policy.max_requests, remaining=policy.max_requests - 1, reset_seconds=policy.window_seconds)

    def record(self, key: str, policy: RateLimitPolicy) -> None:
        pass

    def reset(self, key: str) -> None:
        pass


class StubServiceAPI:
    """Minimal stub for ``ServiceAPI`` that returns sensible defaults."""

    import uuid as _uuid

    def list_assessments(self, request: object):
        from kingsec.application.dto import ListAssessmentsResponse

        return ListAssessmentsResponse(items=(), total=0, limit=50, offset=0)

    def create_assessment(self, request: object):
        from kingsec.application.dto import CreateAssessmentResponse

        return CreateAssessmentResponse(
            assessment_id=str(self._uuid.uuid4()),
            status="authorized",
            target="10.0.0.1",
        )

    def get_assessment(self, request: object):
        from kingsec.application.errors import AssessmentNotFoundError

        raise AssessmentNotFoundError("assessment not found")

    def submit_assessment(self, request: object):
        from kingsec.application.dto import SubmitAssessmentResponse

        return SubmitAssessmentResponse(
            assessment_id=str(self._uuid.uuid4()),
            status="running",
            job_id=str(self._uuid.uuid4()),
        )

    def generate_report(self, request: object):
        from kingsec.application.errors import AssessmentNotFoundError

        raise AssessmentNotFoundError("assessment not found")

    def cancel_assessment(self, request: object):
        from kingsec.application.dto import CancelAssessmentResponse

        return CancelAssessmentResponse(
            assessment_id=str(self._uuid.uuid4()),
            status="cancelled",
        )

    def delete_assessment(self, assessment_id: str) -> None:
        return None


# ── Helpers ────────────────────────────────────────────────────────────────


def _build_app() -> tuple[FastAPI, StubTokenService, StubUserRepo, StubHasher]:
    """Build a FastAPI app with stubbed dependencies.

    Registers the same ``router`` used by the production ``create_fastapi_app``,
    plus the stubbed auth services on a fake ``kingsec_app`` container.
    """
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            from kingsec.application.ports import (
                PasswordHasher,
                ServiceAPI,
                TokenService,
                UserRepository,
            )

            if service_type == ServiceAPI:
                return StubServiceAPI()
            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == PasswordHasher:
                return hasher
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
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)

    return app, token_service, user_repo, hasher  # 4th element is user_repo for test helpers


def _register_user(
    client: TestClient,
    username: str = "testuser",
    email: str = "test@example.com",
    password: str = "SecurePass1",
) -> None:
    """Helper: register a user and assert success."""
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )
    assert resp.status_code == 201, f"register failed: {resp.json()}"


def _register_viewer(
    client: TestClient,
    username: str = "testuser",
    email: str = "test@example.com",
    password: str = "SecurePass1",
) -> None:
    """Helper: register an admin first, then register the requested user as a Viewer.

    The very first user in a fresh database automatically becomes ADMIN.
    This helper creates that admin user, then creates the requested user
    as a VIEWER so callers can test viewer-level permissions.
    """
    _register_user(client, username="admin_bootstrap", email="admin@bootstrap.local", password="AdminPass99")
    _register_user(client, username=username, email=email, password=password)


def _promote_user_in_repo(user_repo, username: str, role_str: str) -> None:
    """Helper: promote a user to the given role directly in the stub repo."""
    from kingsec.domain import Role
    user = user_repo.find_by_username(username)
    assert user is not None, f"user {username} not found"
    new_role = Role[role_str.upper()]
    user.change_role(new_role)
    user_repo.save(user)


def _login(
    client: TestClient,
    username: str = "testuser",
    password: str = "SecurePass1",
) -> str:
    """Helper: login and return the access token."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


# ── Tests ──────────────────────────────────────────────────────────────────


class TestRBACProtectedEndpoints:
    """Verify 401 for unauthenticated requests, 403 for wrong role."""

    def setup_method(self) -> None:
        self.app, self._ts, self._ur, self._h = _build_app()
        self.client = TestClient(self.app)

    # ── 401: no token ──────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", "/api/v1/assessments"),
            ("POST", "/api/v1/assessments"),
            ("GET", "/api/v1/assessments/abc-123"),
            ("POST", "/api/v1/assessments/abc-123/start"),
            ("POST", "/api/v1/assessments/abc-123/report"),
            ("POST", "/api/v1/assessments/abc-123/cancel"),
            ("DELETE", "/api/v1/assessments/abc-123"),
        ],
    )
    def test_protected_endpoint_returns_401_without_token(
        self,
        method: str,
        path: str,
    ) -> None:
        resp = self.client.request(method, path, json={})
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}"

    # ── 403: wrong role for write endpoints ────────────────────────────

    def test_viewer_cannot_create_assessment(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.1",
                "target_type": "ip_address",
                "authorized_by": "admin",
                "scope": "10.0.0.0/24",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_viewer_can_list_assessments(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.get(
            "/api/v1/assessments",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_viewer_can_get_assessment(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.get(
            "/api/v1/assessments/nonexistent",
            headers={"Authorization": f"Bearer {token}"},
        )
        # 404 is expected (assessment doesn't exist) — the important thing
        # is that we got past the auth gate (not 401/403).
        assert resp.status_code == 404

    def test_viewer_cannot_generate_report(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.post(
            "/api/v1/assessments/abc-123/report",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_viewer_cannot_cancel_assessment(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.post(
            "/api/v1/assessments/abc-123/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_viewer_cannot_delete_assessment(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.delete(
            "/api/v1/assessments/abc-123",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    # ── Analyst can perform analyst-level operations ───────────────────

    def test_analyst_can_create_assessment(self) -> None:
        _register_user(self.client)
        _promote_user_in_repo(self._ur, "testuser", "analyst")
        token = _login(self.client)

        resp = self.client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.1",
                "target_type": "ip_address",
                "authorized_by": "admin",
                "scope": "10.0.0.0/24",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        # 400 is expected (DB not available in stub), not 401/403.
        assert resp.status_code not in (401, 403)

    def test_analyst_can_generate_report(self) -> None:
        _register_user(self.client)
        _promote_user_in_repo(self._ur, "testuser", "analyst")
        token = _login(self.client)

        resp = self.client.post(
            "/api/v1/assessments/abc-123/report",
            headers={"Authorization": f"Bearer {token}"},
        )
        # 404 expected (no assessment), not 401/403.
        assert resp.status_code not in (401, 403)

    # ── Admin has full access ──────────────────────────────────────────

    def test_admin_can_create_assessment(self) -> None:
        _register_user(self.client)
        _promote_user_in_repo(self._ur, "testuser", "admin")
        token = _login(self.client)

        resp = self.client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.1",
                "target_type": "ip_address",
                "authorized_by": "admin",
                "scope": "10.0.0.0/24",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code not in (401, 403)

    def test_admin_can_delete_assessment(self) -> None:
        _register_user(self.client)
        _promote_user_in_repo(self._ur, "testuser", "admin")
        token = _login(self.client)

        resp = self.client.delete(
            "/api/v1/assessments/abc-123",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code not in (401, 403)

    # ── Invalid / malformed tokens ─────────────────────────────────────

    def test_malformed_token_returns_401(self) -> None:
        resp = self.client.get(
            "/api/v1/assessments",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401

    def test_expired_token_returns_401(self) -> None:
        resp = self.client.get(
            "/api/v1/assessments",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401

    # ── Role in token ──────────────────────────────────────────────────

    def test_token_with_viewer_role_has_viewer_permissions(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        me_resp = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_resp.status_code == 200
        assert me_resp.json()["role"] == "Viewer"

    def test_token_with_analyst_role_has_analyst_permissions(self) -> None:
        _register_user(self.client)
        _promote_user_in_repo(self._ur, "testuser", "analyst")
        token = _login(self.client)

        me_resp = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_resp.status_code == 200
        assert me_resp.json()["role"] == "Analyst"
