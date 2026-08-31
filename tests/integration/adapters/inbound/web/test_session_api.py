from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user_jwt_only
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.adapters.inbound.web.session_routes import router as sessions_router
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.ports.outbound.token_service import TokenClaims, TokenInvalidError, TokenService
from kingsec.application.ports.outbound.user_repository import UserRepository
from kingsec.application.use_cases.create_session import CreateSession
from kingsec.application.use_cases.list_user_sessions import ListUserSessions
from kingsec.application.use_cases.refresh_session import RefreshSession
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.application.use_cases.revoke_session import RevokeSession
from kingsec.application.use_cases.terminate_other_sessions import TerminateOtherSessions
from kingsec.application.use_cases.validate_session import ValidateSession
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.container import Container
from kingsec.domain import Role, User
from kingsec.domain.session import (
    DeviceInfo,
    Session,
    SessionId,
    SessionStatus,
    SessionType,
)
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.rate_limit.system_clock import SystemClock


class FakeTokenService(TokenService):
    def __init__(self) -> None:
        self.revoked_tokens: set[str] = set()
        # KSEC-75-04: remembers the role/username each create_*_token
        # call was actually given, so verify_*_token can return the
        # role a token was ACTUALLY minted with, rather than a fixed
        # "admin" regardless of input - needed to prove a refreshed
        # token reflects the user's CURRENT role, not a stale one.
        self._issued_role: dict[str, str] = {}
        self._issued_username: dict[str, str] = {}

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        token = f"access_{user_id}"
        self._issued_role[token] = role
        self._issued_username[token] = username
        return token

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        token = f"refresh_{user_id}"
        self._issued_role[token] = role
        self._issued_username[token] = username
        return token

    def verify_access_token(self, token: str) -> TokenClaims:
        jti = "jti_" + token
        if jti in self.revoked_tokens:
            raise TokenInvalidError("token has been revoked")
        return TokenClaims(
            user_id=token.replace("access_", ""),
            username=self._issued_username.get(token, "testuser"),
            role=self._issued_role.get(token, "admin"),
            token_type="access",
            jti=jti,
            issued_at=None,
            expires_at=None,
        )

    def verify_refresh_token(self, token: str) -> TokenClaims:
        jti = "rjti_" + token
        if jti in self.revoked_tokens:
            raise TokenInvalidError("token has been revoked")
        return TokenClaims(
            user_id=token.replace("refresh_", ""),
            username=self._issued_username.get(token, "testuser"),
            role=self._issued_role.get(token, "admin"),
            token_type="refresh",
            jti=jti,
            issued_at=None,
            expires_at=None,
        )

    def create_mfa_pending_token(self, user_id: str, username: str, role: str) -> str:
        return f"pending_{user_id}"

    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        return TokenClaims(
            user_id=token.replace("pending_", ""),
            username="testuser",
            role="admin",
            token_type="mfa_pending",
            jti="pjti_" + token,
            issued_at=None,
            expires_at=None,
        )

    def revoke_token(self, jti: str) -> None:
        self.revoked_tokens.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self.revoked_tokens


class InMemorySessionRepo(SessionRepository):
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}

    def save(self, session: Session) -> None:
        self.sessions[str(session.id)] = session

    def find_by_id(self, session_id: str) -> Session | None:
        return self.sessions.get(session_id)

    def find_by_jti(self, jti: str) -> Session | None:
        for s in self.sessions.values():
            if s.jti == jti:
                return s
        return None

    def find_by_refresh_jti(self, refresh_jti: str) -> Session | None:
        for s in self.sessions.values():
            if s.refresh_jti == refresh_jti:
                return s
        return None

    def find_active_by_user(self, user_id: str) -> list[Session]:
        return [s for s in self.sessions.values() if s.user_id == user_id and s.is_active()]

    def count_active_by_user(self, user_id: str) -> int:
        return len(self.find_active_by_user(user_id))

    def revoke(self, session_id: str) -> None:
        s = self.sessions.get(session_id)
        if s:
            self.sessions[str(s.id)] = Session(
                id=s.id,
                user_id=s.user_id,
                session_type=s.session_type,
                jti=s.jti,
                refresh_jti=s.refresh_jti,
                issued_at=s.issued_at,
                expires_at=s.expires_at,
                last_activity=s.last_activity,
                client_ip=s.client_ip,
                user_agent=s.user_agent,
                device_info=s.device_info,
                status=SessionStatus.REVOKED,
                idle_timeout_seconds=s.idle_timeout_seconds,
            )

    def revoke_all_by_user(self, user_id: str, exclude_session_id: str | None = None) -> None:
        for s in list(self.sessions.values()):
            if s.user_id == user_id and s.is_active():
                if exclude_session_id and str(s.id) == exclude_session_id:
                    continue
                self.revoke(str(s.id))

    def update_activity(self, session_id: str, last_activity: str) -> None:
        pass

    def update_refresh_jti(self, session_id: str, new_refresh_jti: str) -> None:
        s = self.sessions.get(session_id)
        if s:
            self.sessions[str(s.id)] = Session(
                id=s.id,
                user_id=s.user_id,
                session_type=s.session_type,
                jti=s.jti,
                refresh_jti=new_refresh_jti,
                issued_at=s.issued_at,
                expires_at=s.expires_at,
                last_activity=s.last_activity,
                client_ip=s.client_ip,
                user_agent=s.user_agent,
                device_info=s.device_info,
                status=s.status,
                idle_timeout_seconds=s.idle_timeout_seconds,
            )

    def update_access_jti(self, session_id: str, new_access_jti: str) -> None:
        s = self.sessions.get(session_id)
        if s:
            self.sessions[str(s.id)] = Session(
                id=s.id,
                user_id=s.user_id,
                session_type=s.session_type,
                jti=new_access_jti,
                refresh_jti=s.refresh_jti,
                issued_at=s.issued_at,
                expires_at=s.expires_at,
                last_activity=s.last_activity,
                client_ip=s.client_ip,
                user_agent=s.user_agent,
                device_info=s.device_info,
                status=s.status,
                idle_timeout_seconds=s.idle_timeout_seconds,
            )

    def delete_expired(self, before: str) -> int:
        count = 0
        for k in list(self.sessions.keys()):
            if self.sessions[k].expires_at < before:
                del self.sessions[k]
                count += 1
        return count


class InMemoryUserRepo(UserRepository):
    """KSEC-75-04: RefreshSession now re-fetches the user, so this
    fixture app needs a real UserRepository - a plain dict-backed fake,
    pre-populated with an active "u1" matching the other fakes' default
    user_id, so existing session-API tests keep exercising the same
    identity they always have."""

    def __init__(self) -> None:
        self.users: dict[str, User] = {}

    def find_by_username(self, username: str) -> User | None:
        for u in self.users.values():
            if u.username.lower() == username.lower():
                return u
        return None

    def find_by_id(self, user_id: str) -> User | None:
        return self.users.get(user_id)

    def save(self, user: User) -> None:
        self.users[user.id] = user

    def save_new_user_claiming_bootstrap_admin(self, user: User) -> User:
        self.users[user.id] = user
        return user

    def exists_by_username(self, username: str) -> bool:
        return self.find_by_username(username) is not None

    def exists_by_email(self, email: str) -> bool:
        return any(u.email.lower() == email.lower() for u in self.users.values())

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return list(self.users.values())[offset : offset + limit]

    def count(self) -> int:
        return len(self.users)

    def count_by_role(self, role: Role) -> int:
        return sum(1 for u in self.users.values() if u.role == role)

    def search(
        self,
        *,
        query: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "username",
        order_dir: str = "asc",
    ) -> tuple[list[User], int]:
        return ([], 0)


def make_user(user_id: str = "u1", role: Role = Role.ADMIN, is_active: bool = True) -> User:
    return User(
        id=user_id,
        username="testuser",
        email=f"{user_id}@example.com",
        password_hash="hashed:irrelevant",
        role=role,
        is_active=is_active,
    )


async def override_get_current_user() -> CurrentUser:
    return CurrentUser(
        user_id="u1",
        username="testuser",
        role=Role.ADMIN,
        claims=TokenClaims(
            user_id="u1",
            username="testuser",
            role="admin",
            token_type="access",
            jti="test_jti",
            issued_at=None,
            expires_at=None,
        ),
    )


@pytest.fixture
def app() -> FastAPI:
    container = Container()

    repo = InMemorySessionRepo()
    clock: ClockPort = SystemClock()

    container.register_instance(SessionRepository, repo)
    container.register_instance(ClockPort, clock)

    tokens = FakeTokenService()
    container.register_instance(TokenService, tokens)

    users = InMemoryUserRepo()
    users.save(make_user())
    container.register_instance(UserRepository, users)

    container.register_factory(
        CreateSession,
        lambda c: CreateSession(c.resolve(SessionRepository), c.resolve(ClockPort), c.resolve(TokenService)),
    )
    container.register_factory(
        ValidateSession,
        lambda c: ValidateSession(c.resolve(SessionRepository), c.resolve(ClockPort)),
    )
    container.register_factory(
        RefreshSession,
        lambda c: RefreshSession(c.resolve(SessionRepository), c.resolve(TokenService), c.resolve(UserRepository)),
    )
    container.register_factory(
        RevokeSession,
        lambda c: RevokeSession(c.resolve(SessionRepository), c.resolve(TokenService)),
    )
    container.register_factory(
        RevokeAllSessions,
        lambda c: RevokeAllSessions(c.resolve(SessionRepository), c.resolve(TokenService)),
    )
    container.register_factory(
        ListUserSessions,
        lambda c: ListUserSessions(c.resolve(SessionRepository)),
    )
    container.register_factory(
        TerminateOtherSessions,
        lambda c: TerminateOtherSessions(c.resolve(SessionRepository), c.resolve(TokenService)),
    )

    settings = Settings()
    application = Application(
        settings=settings,
        container=container,
        exception_handlers=None,
        logger=None,
        ensure_directories=False,
    )

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
    fastapi_app.dependency_overrides[get_current_user_jwt_only] = override_get_current_user
    fastapi_app.include_router(sessions_router)
    register_error_handlers(fastapi_app)

    return fastapi_app


def make_session(
    sid: str = "s1",
    user_id: str = "u1",
    jti: str = "jti1",
    refresh_jti: str = "rjti1",
    status: SessionStatus = SessionStatus.ACTIVE,
) -> Session:
    return Session(
        id=SessionId(value=sid),
        user_id=user_id,
        session_type=SessionType.USER,
        jti=jti,
        refresh_jti=refresh_jti,
        issued_at="2025-01-01T00:00:00+00:00",
        expires_at="2025-01-08T00:00:00+00:00",
        last_activity="2025-01-01T00:00:00+00:00",
        client_ip="1.2.3.4",
        user_agent="curl",
        device_info=DeviceInfo(platform="Windows", browser="Chrome"),
        status=status,
        idle_timeout_seconds=1800,
    )


class TestSessionAPI:
    def test_list_sessions_empty(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.get("/api/v1/sessions")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_sessions(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s1"),
                user_id="u1",
                session_type=SessionType.USER,
                jti="jti1",
                refresh_jti="rjti1",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
                device_info=DeviceInfo(platform="Windows", browser="Chrome"),
            )
        )
        client = TestClient(app)
        resp = client.get("/api/v1/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == "s1"
        assert data[0]["jti"] == "jti1"
        assert data[0]["status"] == "active"

    def test_get_current_session(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s1"),
                user_id="u1",
                session_type=SessionType.USER,
                jti="test_jti",
                refresh_jti="rjti1",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
                device_info=DeviceInfo(platform="Linux", browser="Firefox"),
            )
        )
        client = TestClient(app)
        resp = client.get("/api/v1/sessions/current")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "s1"
        assert data["client_ip"] == "1.2.3.4"

    def test_logout_current(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s1"),
                user_id="u1",
                session_type=SessionType.USER,
                jti="test_jti",
                refresh_jti="rjti1",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
            )
        )
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        client = TestClient(app)
        resp = client.delete("/api/v1/sessions/current")
        assert resp.status_code == 204
        assert repo.find_by_id("s1").status == SessionStatus.REVOKED
        assert "test_jti" in tokens.revoked_tokens
        assert "rjti1" in tokens.revoked_tokens

    def test_logout_current_without_session_row_still_revokes_access_token(self, app: FastAPI) -> None:
        """KSEC-75-05: reproduces the exact Phase 75 condition - a valid
        JWT with NO corresponding Session row (e.g. because
        create_session_for_login's documented best-effort session
        recording silently failed for this login). Logout must still
        return its normal success response AND actually revoke the
        caller's access-token jti - not silently no-op."""
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        # Deliberately no session saved for "test_jti" - repo is empty.
        assert repo.find_by_jti("test_jti") is None

        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        client = TestClient(app)
        resp = client.delete("/api/v1/sessions/current")

        assert resp.status_code == 204
        assert "test_jti" in tokens.revoked_tokens
        assert tokens.is_revoked("test_jti")

    def test_logout_current_cannot_revoke_another_users_token(self, app: FastAPI) -> None:
        """Wrong-user isolation: logout only ever revokes the CALLER's
        own access-token jti (current_user.claims.jti), which comes from
        their own verified JWT - there is no request parameter that
        could name a different user's token."""
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s-other"),
                user_id="u-other",
                session_type=SessionType.USER,
                jti="other_users_jti",
                refresh_jti="other_users_rjti",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
            )
        )
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        client = TestClient(app)
        resp = client.delete("/api/v1/sessions/current")

        assert resp.status_code == 204
        assert "other_users_jti" not in tokens.revoked_tokens
        assert "other_users_rjti" not in tokens.revoked_tokens
        assert repo.find_by_id("s-other").status == SessionStatus.ACTIVE

    def test_logout_all(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        for i in range(3):
            repo.save(
                Session(
                    id=SessionId(value=f"s{i}"),
                    user_id="u1",
                    session_type=SessionType.USER,
                    jti=f"jti{i}",
                    refresh_jti=f"rjti{i}",
                    issued_at="2025-01-01T00:00:00+00:00",
                    expires_at="2025-01-08T00:00:00+00:00",
                    last_activity="2025-01-01T00:00:00+00:00",
                    client_ip="1.2.3.4",
                    user_agent="curl",
                )
            )
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        client = TestClient(app)
        resp = client.delete("/api/v1/sessions")
        assert resp.status_code == 204
        for i in range(3):
            assert repo.find_by_id(f"s{i}").status == SessionStatus.REVOKED
            assert f"jti{i}" in tokens.revoked_tokens
            assert f"rjti{i}" in tokens.revoked_tokens

    def test_refresh_revokes_old_tokens_and_updates_session(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s1"),
                user_id="u1",
                session_type=SessionType.USER,
                jti="test_jti",
                refresh_jti="rjti_refresh_u1",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
            )
        )
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)

        client = TestClient(app)
        resp = client.post("/api/v1/sessions/refresh", json={"refresh_token": "refresh_u1"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

        # Old access and refresh JTIs must be revoked
        assert "test_jti" in tokens.revoked_tokens
        assert "rjti_refresh_u1" in tokens.revoked_tokens

        # Session must be updated with the new JTIs
        updated = repo.find_by_id("s1")
        assert updated is not None
        assert updated.jti == "jti_access_u1"
        assert updated.refresh_jti == "rjti_refresh_u1"

    def test_refresh_rejected_after_deactivation(self, app: FastAPI) -> None:
        """KSEC-75-04 / Attack 4: a deactivated user's refresh token must
        be rejected by POST /api/v1/sessions/refresh on the FIRST
        attempt - not merely eventually, and not merely by /auth/refresh."""
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s1"),
                user_id="u1",
                session_type=SessionType.USER,
                jti="test_jti",
                refresh_jti="rjti_refresh_u1",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
            )
        )
        users: InMemoryUserRepo = app.state.kingsec_app.resolve(UserRepository)
        users.users["u1"].is_active = False

        client = TestClient(app)
        resp = client.post("/api/v1/sessions/refresh", json={"refresh_token": "refresh_u1"})

        assert resp.status_code == 401
        # Nothing was rotated or revoked - the rejection happened before
        # any session/token mutation.
        unchanged = repo.find_by_id("s1")
        assert unchanged.jti == "test_jti"
        assert unchanged.refresh_jti == "rjti_refresh_u1"
        assert unchanged.status == SessionStatus.ACTIVE

    def test_refresh_reflects_current_role_after_role_change(self, app: FastAPI) -> None:
        """KSEC-75-04: a role change must be reflected on the very next
        /sessions/refresh call, not just on /auth/refresh."""
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(
            Session(
                id=SessionId(value="s1"),
                user_id="u1",
                session_type=SessionType.USER,
                jti="test_jti",
                refresh_jti="rjti_refresh_u1",
                issued_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-01-08T00:00:00+00:00",
                last_activity="2025-01-01T00:00:00+00:00",
                client_ip="1.2.3.4",
                user_agent="curl",
            )
        )
        users: InMemoryUserRepo = app.state.kingsec_app.resolve(UserRepository)
        users.users["u1"].role = Role.VIEWER  # demoted from the fixture's default Role.ADMIN

        client = TestClient(app)
        resp = client.post("/api/v1/sessions/refresh", json={"refresh_token": "refresh_u1"})

        assert resp.status_code == 200
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        new_access_token = resp.json()["access_token"]
        new_claims = tokens.verify_access_token(new_access_token)
        assert new_claims.role == "Viewer"
        assert new_claims.role != "Admin"

    def test_revoke_all_excluded_tokens_not_revoked(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        for i in range(3):
            repo.save(
                Session(
                    id=SessionId(value=f"s{i}"),
                    user_id="u1",
                    session_type=SessionType.USER,
                    jti=f"jti{i}",
                    refresh_jti=f"rjti{i}",
                    issued_at="2025-01-01T00:00:00+00:00",
                    expires_at="2025-01-08T00:00:00+00:00",
                    last_activity="2025-01-01T00:00:00+00:00",
                    client_ip="1.2.3.4",
                    user_agent="curl",
                )
            )
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        revoke_all: RevokeAllSessions = app.state.kingsec_app.resolve(RevokeAllSessions)
        from kingsec.application.use_cases.session_dto import RevokeAllSessionsRequest
        resp = revoke_all.execute(RevokeAllSessionsRequest(user_id="u1", exclude_session_id="s0"))
        assert resp.revoked_count == 3
        assert repo.find_by_id("s0").status == SessionStatus.ACTIVE
        assert "jti0" not in tokens.revoked_tokens
        assert "rjti0" not in tokens.revoked_tokens
        assert "jti1" in tokens.revoked_tokens
        assert "jti2" in tokens.revoked_tokens

    def test_terminate_other_sessions_revokes_other_tokens(self, app: FastAPI) -> None:
        repo: InMemorySessionRepo = app.state.kingsec_app.resolve(SessionRepository)
        repo.save(make_session(sid="s1"))
        repo.save(make_session(sid="s2", jti="jti2", refresh_jti="rjti2"))
        repo.save(make_session(sid="s3", jti="jti3", refresh_jti="rjti3"))
        tokens: FakeTokenService = app.state.kingsec_app.resolve(TokenService)
        terminate: TerminateOtherSessions = app.state.kingsec_app.resolve(TerminateOtherSessions)
        from kingsec.application.use_cases.session_dto import TerminateOtherSessionsRequest
        resp = terminate.execute(TerminateOtherSessionsRequest(user_id="u1", current_session_id="s1"))
        assert resp.terminated_count == 3
        assert repo.find_by_id("s1").status == SessionStatus.ACTIVE
        assert repo.find_by_id("s2").status == SessionStatus.REVOKED
        assert repo.find_by_id("s3").status == SessionStatus.REVOKED
        assert "jti1" not in tokens.revoked_tokens
        assert "rjti1" not in tokens.revoked_tokens
        assert "jti2" in tokens.revoked_tokens
        assert "rjti2" in tokens.revoked_tokens
        assert "jti3" in tokens.revoked_tokens
        assert "rjti3" in tokens.revoked_tokens
