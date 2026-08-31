from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from kingsec.application.ports import TokenClaims, TokenService, UserRepository
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.ports.outbound.token_service import TokenInvalidError
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
from kingsec.domain import Role, User
from kingsec.domain.session import (
    DeviceInfo,
    Session,
    SessionId,
    SessionStatus,
    SessionType,
)


@dataclass
class FakeUserRepository(UserRepository):
    """Minimal UserRepository fake for session use-case tests - KSEC-75-04
    needs RefreshSession to re-fetch the current user, so its tests need
    a real (if simple) UserRepository, not just Session/Token fakes."""

    users: dict[str, User] = field(default_factory=dict)

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


def make_user(user_id: str = "u1", role: Role = Role.VIEWER, is_active: bool = True) -> User:
    return User(
        id=user_id,
        username=f"user_{user_id}",
        email=f"{user_id}@example.com",
        password_hash="hashed:irrelevant",
        role=role,
        is_active=is_active,
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
    """A real, working fake: create_*_token/verify_*_token round-trip
    through an in-memory table, rather than the previous stub shape
    (create returning "", verify raising NotImplementedError) - needed
    now that RefreshSession (KSEC-75-04) mints tokens internally and
    immediately verifies them to extract the new jti, exactly like
    JWTTokenService's real callers do."""

    revoked: set[str] = field(default_factory=set)
    _tokens: dict[str, TokenClaims] = field(default_factory=dict)

    def _mint(self, user_id: str, username: str, role: str, token_type: str) -> str:
        jti = uuid.uuid4().hex
        token = f"{token_type}:{jti}"
        now = datetime.now(UTC)
        self._tokens[token] = TokenClaims(
            user_id=user_id,
            username=username,
            role=role,
            token_type=token_type,
            jti=jti,
            issued_at=now,
            expires_at=now,
        )
        return token

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        return self._mint(user_id, username, role, "access")

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        return self._mint(user_id, username, role, "refresh")

    def create_mfa_pending_token(self, user_id: str, username: str, role: str) -> str:
        return self._mint(user_id, username, role, "mfa_pending")

    def _verify(self, token: str, expected_type: str) -> TokenClaims:
        claims = self._tokens.get(token)
        if claims is None or claims.token_type != expected_type:
            raise TokenInvalidError(f"expected {expected_type} token")
        if claims.jti in self.revoked:
            raise TokenInvalidError("token has been revoked")
        return claims

    def verify_access_token(self, token: str) -> TokenClaims:
        return self._verify(token, "access")

    def verify_refresh_token(self, token: str) -> TokenClaims:
        return self._verify(token, "refresh")

    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        return self._verify(token, "mfa_pending")

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
    """KSEC-75-04: RefreshSession must re-fetch the current user and
    reject/reflect current account state, never trusting the old
    refresh token's own claims - see the module-level FakeUserRepository/
    make_user helpers."""

    def test_valid_refresh_active_user(self) -> None:
        """Test A: an active user with a valid refresh token can
        successfully refresh, and the resulting tokens carry the
        CURRENT user identity/role."""
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        users = FakeUserRepository()
        users.save(make_user(user_id="u1", role=Role.ANALYST))
        uc = RefreshSession(repo, tokens, users)

        resp = uc.execute(RefreshSessionRequest(user_id="u1", old_refresh_jti="rjti1"))

        assert resp.valid
        assert not resp.replay_detected
        assert resp.access_token is not None
        assert resp.refresh_token is not None

        new_access_claims = tokens.verify_access_token(resp.access_token)
        assert new_access_claims.user_id == "u1"
        assert new_access_claims.role == Role.ANALYST.label

        updated = repo.find_by_id("s1")
        # The session's tracked JTIs were rotated to the newly-minted tokens' jtis.
        assert updated.refresh_jti == tokens.verify_refresh_token(resp.refresh_token).jti
        assert updated.jti == new_access_claims.jti
        # The OLD jtis were revoked.
        assert "rjti1" in tokens.revoked
        assert "jti1" in tokens.revoked

    def test_deactivated_user_refresh_rejected(self) -> None:
        """Test B: login, obtain refresh token, deactivate the user,
        attempt refresh - it MUST fail, and MUST NOT mint new tokens or
        touch the session."""
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        users = FakeUserRepository()
        users.save(make_user(user_id="u1", role=Role.VIEWER, is_active=False))
        uc = RefreshSession(repo, tokens, users)

        resp = uc.execute(RefreshSessionRequest(user_id="u1", old_refresh_jti="rjti1"))

        assert not resp.valid
        assert not resp.replay_detected
        assert resp.access_token is None
        assert resp.refresh_token is None
        # The (still-active-looking) session row is untouched - the
        # rejection happened before any rotation/revocation occurred.
        unchanged = repo.find_by_id("s1")
        assert unchanged.jti == "jti1"
        assert unchanged.refresh_jti == "rjti1"
        assert unchanged.status == SessionStatus.ACTIVE
        assert tokens.revoked == set()

    def test_role_change_reflected_on_refresh(self) -> None:
        """Test C: login as Admin, change the user to Viewer, refresh -
        the new access token MUST reflect Viewer, MUST NOT carry Admin."""
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        users = FakeUserRepository()
        users.save(make_user(user_id="u1", role=Role.ADMIN))
        uc = RefreshSession(repo, tokens, users)

        # Demote the user in the database, as AssignRole would.
        users.users["u1"].role = Role.VIEWER

        resp = uc.execute(RefreshSessionRequest(user_id="u1", old_refresh_jti="rjti1"))

        assert resp.valid
        new_claims = tokens.verify_access_token(resp.access_token)
        assert new_claims.role == Role.VIEWER.label
        assert new_claims.role != Role.ADMIN.label

    def test_nonexistent_user_refresh_rejected(self) -> None:
        """Test D: a refresh token for a user_id that no longer exists
        in UserRepository (deleted account) must be rejected."""
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        users = FakeUserRepository()  # deliberately empty - "u1" does not exist
        uc = RefreshSession(repo, tokens, users)

        resp = uc.execute(RefreshSessionRequest(user_id="u1", old_refresh_jti="rjti1"))

        assert not resp.valid
        assert not resp.replay_detected
        assert resp.access_token is None

    def test_replay_detected(self) -> None:
        """Test E: existing refresh-token rotation and replay/reuse
        detection must still work after the KSEC-75-04 remediation."""
        repo = FakeSessionRepository()
        repo.save(make_session())
        tokens = FakeTokenService()
        users = FakeUserRepository()
        users.save(make_user(user_id="u1", role=Role.VIEWER))
        uc = RefreshSession(repo, tokens, users)

        resp1 = uc.execute(RefreshSessionRequest(user_id="u1", old_refresh_jti="rjti1"))
        assert resp1.valid
        assert "rjti1" in tokens.revoked
        assert "jti1" in tokens.revoked
        rotated_refresh_jti = tokens.verify_refresh_token(resp1.refresh_token).jti
        rotated_access_jti = tokens.verify_access_token(resp1.access_token).jti

        tokens.revoked.clear()
        # Replay: present the ALREADY-ROTATED-OUT old refresh_jti again.
        resp2 = uc.execute(RefreshSessionRequest(user_id="u1", old_refresh_jti="rjti1"))
        assert not resp2.valid
        assert resp2.replay_detected
        assert repo.find_by_id("s1").status == SessionStatus.REVOKED
        # Replay path revokes the current (post-first-refresh) JTIs.
        assert rotated_access_jti in tokens.revoked
        assert rotated_refresh_jti in tokens.revoked

    def test_unknown_refresh_jti(self) -> None:
        repo = FakeSessionRepository()
        tokens = FakeTokenService()
        users = FakeUserRepository()
        users.save(make_user(user_id="u1"))
        uc = RefreshSession(repo, tokens, users)
        req = RefreshSessionRequest(user_id="u1", old_refresh_jti="nonexistent")
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
