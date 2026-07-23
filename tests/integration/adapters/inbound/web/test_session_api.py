from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.adapters.inbound.web.session_routes import router as sessions_router
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.ports.outbound.token_service import TokenClaims, TokenService
from kingsec.application.use_cases.create_session import CreateSession
from kingsec.application.use_cases.list_user_sessions import ListUserSessions
from kingsec.application.use_cases.refresh_session import RefreshSession
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.application.use_cases.revoke_session import RevokeSession
from kingsec.application.use_cases.terminate_other_sessions import TerminateOtherSessions
from kingsec.application.use_cases.validate_session import ValidateSession
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.container import Container
from kingsec.domain import Role
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

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        return f"access_{user_id}"

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        return f"refresh_{user_id}"

    def verify_access_token(self, token: str) -> TokenClaims:
        return TokenClaims(
            user_id=token.replace("access_", ""),
            username="testuser",
            role="admin",
            token_type="access",
            jti="jti_" + token,
            issued_at=None,
            expires_at=None,
        )

    def verify_refresh_token(self, token: str) -> TokenClaims:
        return TokenClaims(
            user_id=token.replace("refresh_", ""),
            username="testuser",
            role="admin",
            token_type="refresh",
            jti="rjti_" + token,
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

    container.register_factory(
        CreateSession,
        lambda c: CreateSession(c.resolve(SessionRepository), c.resolve(ClockPort)),
    )
    container.register_factory(
        ValidateSession,
        lambda c: ValidateSession(c.resolve(SessionRepository), c.resolve(ClockPort)),
    )
    container.register_factory(
        RefreshSession,
        lambda c: RefreshSession(c.resolve(SessionRepository), c.resolve(TokenService)),
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
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user
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
