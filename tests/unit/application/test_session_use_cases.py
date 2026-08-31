from __future__ import annotations

from dataclasses import dataclass, field

from kingsec.application.ports import TokenClaims, TokenService
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.create_session import CreateSession
from kingsec.application.use_cases.list_user_sessions import ListUserSessions
from kingsec.application.use_cases.refresh_session import RefreshSession
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.application.use_cases.revoke_session import RevokeSession
from kingsec.application.use_cases.session_dto import (
    CreateSessionRequest,
    ListUserSessionsRequest,
    RefreshSessionRequest,
    RevokeAllSessionsRequest,
    RevokeSessionRequest,
    TerminateOtherSessionsRequest,
    ValidateSessionRequest,
)
from kingsec.application.use_cases.terminate_other_sessions import (
    TerminateOtherSessions,
)
from kingsec.application.use_cases.validate_session import ValidateSession
from kingsec.domain.session import (
    DeviceInfo,
    Session,
    SessionId,
    SessionStatus,
    SessionType,
)


@dataclass
class FakeSessionRepository(SessionRepository):
    sessions: dict[str, Session] = field(default_factory=dict)

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
        for s in self.sessions.values():
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
        to_delete = [k for k, s in self.sessions.items() if s.expires_at < before]
        for k in to_delete:
            del self.sessions[k]
            count += 1
        return count


@dataclass
class FakeTokenService(TokenService):
    revoked: set[str] = field(default_factory=set)

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        return ""

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        return ""

    def create_mfa_pending_token(self, user_id: str, username: str, role: str) -> str:
        return ""

    def verify_access_token(self, token: str) -> TokenClaims:
        raise NotImplementedError

    def verify_refresh_token(self, token: str) -> TokenClaims:
        raise NotImplementedError

    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        raise NotImplementedError

    def revoke_token(self, jti: str) -> None:
        self.revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self.revoked


@dataclass
class FakeClock(ClockPort):
    _now: float = 1000.0

    def now(self) -> float:
        return self._now


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
        user_agent="Mozilla/5.0",
        device_info=DeviceInfo(platform="Windows", browser="Chrome"),
        status=status,
        idle_timeout_seconds=1800,
    )


class TestCreateSession:
    def test_creates_session(self) -> None:
        repo = FakeSessionRepository()
        clock = FakeClock()
        tokens = FakeTokenService()
        uc = CreateSession(repo, clock, tokens, max_concurrent_sessions=5)
        req = CreateSessionRequest(
            user_id="u1",
            jti="jti_new",
            refresh_jti="rjti_new",
            client_ip="1.2.3.4",
            user_agent="curl",
        )
        resp = uc.execute(req)
        assert resp.session_id
        saved = repo.find_by_id(resp.session_id)
        assert saved is not None
        assert saved.user_id == "u1"
        assert saved.jti == "jti_new"

    def test_revokes_oldest_when_at_limit(self) -> None:
        repo = FakeSessionRepository()
        clock = FakeClock()
        tokens = FakeTokenService()
        for i in range(5):
            s = make_session(sid=f"s{i}", jti=f"jti{i}", refresh_jti=f"rjti{i}")
            repo.save(s)
        uc = CreateSession(repo, clock, tokens, max_concurrent_sessions=5)
        req = CreateSessionRequest(
            user_id="u1",
            jti="jti_new",
            refresh_jti="rjti_new",
            client_ip="1.2.3.4",
            user_agent="curl",
        )
        uc.execute(req)
        assert repo.find_by_id("s0") is None or repo.find_by_id("s0").status == SessionStatus.REVOKED
        assert repo.count_active_by_user("u1") <= 5

    def test_evicted_sessions_jwts_are_actually_revoked(self) -> None:
        """KSEC-73-02: eviction must revoke the evicted session's jti AND
        refresh_jti in the real TokenService store the JWT-verification
        path consults - not merely flip the Session row's own status."""
        repo = FakeSessionRepository()
        clock = FakeClock()
        tokens = FakeTokenService()
        for i in range(5):
            s = make_session(sid=f"s{i}", jti=f"jti{i}", refresh_jti=f"rjti{i}")
            repo.save(s)
        uc = CreateSession(repo, clock, tokens, max_concurrent_sessions=5)

        uc.execute(
            CreateSessionRequest(
                user_id="u1", jti="jti_new", refresh_jti="rjti_new", client_ip="1.2.3.4", user_agent="curl"
            )
        )

        # s0 is the oldest (issued_at is identical across make_session's
        # default, but s0 is inserted first and is the one the existing
        # test above already asserts gets evicted).
        evicted = repo.find_by_id("s0")
        assert evicted is not None
        assert evicted.status == SessionStatus.REVOKED
        assert tokens.is_revoked("jti0")
        assert tokens.is_revoked("rjti0")

        # The sixth (new) session's own tokens must NOT be revoked.
        assert not tokens.is_revoked("jti_new")
        assert not tokens.is_revoked("rjti_new")

    def test_no_eviction_below_limit_revokes_nothing(self) -> None:
        repo = FakeSessionRepository()
        clock = FakeClock()
        tokens = FakeTokenService()
        uc = CreateSession(repo, clock, tokens, max_concurrent_sessions=5)

        uc.execute(
            CreateSessionRequest(
                user_id="u1", jti="jti_new", refresh_jti="rjti_new", client_ip="1.2.3.4", user_agent="curl"
            )
        )

        assert tokens.revoked == set()


class TestValidateSession:
    def test_valid_session(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session())
        clock = FakeClock()
        uc = ValidateSession(repo, clock)
        req = ValidateSessionRequest(jti="jti1", user_id="u1")
        resp = uc.execute(req)
        assert resp.valid
        assert resp.session_id == "s1"

    def test_invalid_missing_jti(self) -> None:
        repo = FakeSessionRepository()
        clock = FakeClock()
        uc = ValidateSession(repo, clock)
        req = ValidateSessionRequest(jti="nonexistent", user_id="u1")
        resp = uc.execute(req)
        assert not resp.valid

    def test_revoked_session_not_valid(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session(status=SessionStatus.REVOKED))
        clock = FakeClock()
        uc = ValidateSession(repo, clock)
        req = ValidateSessionRequest(jti="jti1", user_id="u1")
        resp = uc.execute(req)
        assert not resp.valid


class TestRefreshSession:
    def test_valid_refresh(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        uc = RefreshSession(repo, tokens)
        req = RefreshSessionRequest(
            user_id="u1",
            old_refresh_jti="rjti1",
            new_refresh_jti="rjti_new",
            new_access_jti="jti_new",
        )
        resp = uc.execute(req)
        assert resp.valid
        assert not resp.replay_detected
        updated = repo.find_by_id("s1")
        assert updated.refresh_jti == "rjti_new"
        assert updated.jti == "jti_new"
        assert "rjti1" in tokens.revoked
        assert "jti1" in tokens.revoked

    def test_replay_detected(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        uc = RefreshSession(repo, tokens)
        req1 = RefreshSessionRequest(
            user_id="u1",
            old_refresh_jti="rjti1",
            new_refresh_jti="rjti_new",
            new_access_jti="jti_new",
        )
        resp1 = uc.execute(req1)
        assert resp1.valid
        assert "rjti1" in tokens.revoked
        assert "jti1" in tokens.revoked

        tokens.revoked.clear()
        req2 = RefreshSessionRequest(
            user_id="u1",
            old_refresh_jti="rjti1",
            new_refresh_jti="rjti_replay",
            new_access_jti="jti_replay",
        )
        resp2 = uc.execute(req2)
        assert not resp2.valid
        assert resp2.replay_detected
        assert repo.find_by_id("s1").status == SessionStatus.REVOKED
        # Replay path revokes the current (post-refresh) JTIs
        assert "jti_new" in tokens.revoked
        assert "rjti_new" in tokens.revoked

    def test_unknown_refresh_jti(self) -> None:
        repo = FakeSessionRepository()
        tokens = FakeTokenService()
        uc = RefreshSession(repo, tokens)
        req = RefreshSessionRequest(
            user_id="u1",
            old_refresh_jti="nonexistent",
            new_refresh_jti="rjti_new",
            new_access_jti="jti_new",
        )
        resp = uc.execute(req)
        assert not resp.valid
        assert not resp.replay_detected
        assert len(tokens.revoked) == 0


class TestRevokeSession:
    def test_revokes_existing(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        uc = RevokeSession(repo, tokens)
        resp = uc.execute(RevokeSessionRequest(session_id="s1"))
        assert resp.success
        assert repo.find_by_id("s1").status == SessionStatus.REVOKED
        assert "jti1" in tokens.revoked
        assert "rjti1" in tokens.revoked

    def test_nonexistent_session(self) -> None:
        repo = FakeSessionRepository()
        tokens = FakeTokenService()
        uc = RevokeSession(repo, tokens)
        resp = uc.execute(RevokeSessionRequest(session_id="nonexistent"))
        assert not resp.success
        assert len(tokens.revoked) == 0


class TestRevokeAllSessions:
    def test_revokes_all(self) -> None:
        repo = FakeSessionRepository()
        for i in range(3):
            repo.save(make_session(sid=f"s{i}", jti=f"jti{i}", refresh_jti=f"rjti{i}"))
        tokens = FakeTokenService()
        uc = RevokeAllSessions(repo, tokens)
        resp = uc.execute(RevokeAllSessionsRequest(user_id="u1"))
        assert resp.revoked_count == 3
        for i in range(3):
            assert repo.find_by_id(f"s{i}").status == SessionStatus.REVOKED
            assert f"jti{i}" in tokens.revoked
            assert f"rjti{i}" in tokens.revoked

    def test_excludes_current(self) -> None:
        repo = FakeSessionRepository()
        for i in range(3):
            repo.save(make_session(sid=f"s{i}", jti=f"jti{i}", refresh_jti=f"rjti{i}"))
        tokens = FakeTokenService()
        uc = RevokeAllSessions(repo, tokens)
        resp = uc.execute(RevokeAllSessionsRequest(user_id="u1", exclude_session_id="s0"))
        assert resp.revoked_count == 3
        assert repo.find_by_id("s0").status == SessionStatus.ACTIVE
        assert "jti0" not in tokens.revoked
        assert "rjti0" not in tokens.revoked
        assert "jti1" in tokens.revoked
        assert "rjti1" in tokens.revoked
        assert "jti2" in tokens.revoked
        assert "rjti2" in tokens.revoked


class TestListUserSessions:
    def test_lists_active(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session(sid="s1"))
        repo.save(make_session(sid="s2", jti="jti2", refresh_jti="rjti2"))
        repo.save(make_session(sid="s3", jti="jti3", refresh_jti="rjti3", status=SessionStatus.REVOKED))
        uc = ListUserSessions(repo)
        resp = uc.execute(ListUserSessionsRequest(user_id="u1"))
        assert len(resp.sessions) == 2

    def test_empty(self) -> None:
        repo = FakeSessionRepository()
        uc = ListUserSessions(repo)
        resp = uc.execute(ListUserSessionsRequest(user_id="u1"))
        assert len(resp.sessions) == 0


class TestTerminateOtherSessions:
    def test_terminates_others(self) -> None:
        repo = FakeSessionRepository()
        repo.save(make_session(sid="s1"))
        repo.save(make_session(sid="s2", jti="jti2", refresh_jti="rjti2"))
        repo.save(make_session(sid="s3", jti="jti3", refresh_jti="rjti3"))
        tokens = FakeTokenService()
        uc = TerminateOtherSessions(repo, tokens)
        resp = uc.execute(TerminateOtherSessionsRequest(user_id="u1", current_session_id="s1"))
        assert resp.terminated_count == 3
        assert repo.find_by_id("s1").status == SessionStatus.ACTIVE
        assert repo.find_by_id("s2").status == SessionStatus.REVOKED
        assert repo.find_by_id("s3").status == SessionStatus.REVOKED
        assert "jti1" not in tokens.revoked
        assert "rjti1" not in tokens.revoked
        assert "jti2" in tokens.revoked
        assert "rjti2" in tokens.revoked
        assert "jti3" in tokens.revoked
        assert "rjti3" in tokens.revoked
