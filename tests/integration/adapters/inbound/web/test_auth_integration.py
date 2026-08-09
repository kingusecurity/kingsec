"""Integration test: full authentication flow via HTTP endpoints.

Verifies the complete lifecycle:
  1. Register a new user
  2. Login with the new user
  3. Use access token to access protected endpoint
  4. Refresh the access token
  5. Verify role-based access control
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.ports import TokenClaims, TokenService
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain import User
from kingsec.domain.mfa import MfaSecret
from kingsec.domain.rate_limit import AccountLockout, LockoutPolicy, RateLimitDecision, RateLimitPolicy
from kingsec.infrastructure.config import Settings


class StubTokenService(TokenService):
    """Minimal token service for integration testing."""

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
    """In-memory user store for integration testing."""

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
    """Stub password hasher for integration testing."""

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
    def check(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        return RateLimitDecision(allowed=True, limit=policy.max_requests, remaining=policy.max_requests - 1, reset_seconds=policy.window_seconds)
    def record(self, key: str, policy: RateLimitPolicy) -> None:
        pass
    def reset(self, key: str) -> None:
        pass


def _build_app() -> tuple[FastAPI, StubTokenService, StubUserRepo]:
    """Build a FastAPI app with stubbed dependencies."""
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            from kingsec.application.ports import PasswordHasher, TokenService, UserRepository

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
            if service_type == CheckRateLimit:
                return CheckRateLimit(StubRateLimiter())
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)

    return app, token_service, user_repo


class TestAuthFlowIntegration:
    """Full authentication lifecycle tests."""

    def test_register_login_me_lifecycle(self) -> None:
        """Register → Login → GET /me with token."""
        app, _token_service, _user_repo = _build_app()
        client = TestClient(app)

        # Step 1: Register (first user becomes Admin)
        register_resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "newuser",
                "email": "new@example.com",
                "password": "SecurePass1",
            },
        )
        assert register_resp.status_code == 201
        body = register_resp.json()
        assert body["username"] == "newuser"
        assert body["role"] == "Admin"

        # Step 2: Login
        login_resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "newuser",
                "password": "SecurePass1",
            },
        )
        assert login_resp.status_code == 200
        login_body = login_resp.json()
        assert "access_token" in login_body
        assert "refresh_token" in login_body
        access_token = login_body["access_token"]

        # Step 3: GET /me with token
        me_resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_resp.status_code == 200
        me_body = me_resp.json()
        assert me_body["username"] == "newuser"
        assert me_body["role"] == "Admin"

    def test_refresh_token_lifecycle(self) -> None:
        """Login → Refresh → use new access token."""
        app, _token_service, _user_repo = _build_app()
        client = TestClient(app)

        # Register + Login
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "refreshuser",
                "email": "refresh@example.com",
                "password": "SecurePass1",
            },
        )
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "refreshuser", "password": "SecurePass1"},
        )
        refresh_token = login_resp.json()["refresh_token"]

        # Refresh
        refresh_resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 200
        new_access = refresh_resp.json()["access_token"]

        # Use new access token
        me_resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {new_access}"},
        )
        assert me_resp.status_code == 200

    def test_missing_token_returns_401(self) -> None:
        app, _, _ = _build_app()
        client = TestClient(app)

        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self) -> None:
        app, _, _ = _build_app()
        client = TestClient(app)

        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401

    def test_wrong_role_returns_403(self) -> None:
        app, _token_service, _user_repo = _build_app()
        client = TestClient(app)

        # Register admin (first user becomes Admin)
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "admin_bootstrap",
                "email": "admin@bootstrap.local",
                "password": "AdminPass99",
            },
        )
        # Register viewer (second user becomes Viewer)
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "viewer",
                "email": "viewer@example.com",
                "password": "SecurePass1",
            },
        )
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "viewer", "password": "SecurePass1"},
        )
        access_token = login_resp.json()["access_token"]

        # Try to create assessment (requires analyst)
        create_resp = client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.1",
                "target_type": "ip_address",
                "authorized_by": "admin",
                "scope": "10.0.0.0/24",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert create_resp.status_code == 403
