"""Tests for Login use case."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.dto import LoginRequest
from kingsec.application.ports import PasswordHasher, TokenClaims, TokenService, UserRepository
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.use_cases.login import AuthenticationError, Login
from kingsec.domain import Role, User
from kingsec.domain.rate_limit import AccountLockout, LockoutPolicy

# --- Stubs --------------------------------------------------------------------


class StubPasswordHasher(PasswordHasher):
    def __init__(self, verify_result: bool = True) -> None:
        self._verify_result = verify_result
        self.hash_called = False
        self.verify_called = False

    def hash(self, password: str) -> str:
        self.hash_called = True
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str) -> bool:
        self.verify_called = True
        return self._verify_result


class StubTokenService(TokenService):
    def __init__(self) -> None:
        self.create_access_called = False
        self.create_refresh_called = False

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        self.create_access_called = True
        return f"access-token-{user_id}"

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        self.create_refresh_called = True
        return f"refresh-token-{user_id}"

    def verify_access_token(self, token: str) -> TokenClaims:
        return TokenClaims(
            user_id="user-001",
            username="test",
            role="Viewer",
            token_type="access",
            jti="jti-1",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )

    def verify_refresh_token(self, token: str) -> TokenClaims:
        return self.verify_access_token(token)

    def revoke_token(self, jti: str) -> None:
        pass

    def is_revoked(self, jti: str) -> bool:
        return False


class StubUserRepository(UserRepository):
    def __init__(self, user: User | None = None) -> None:
        self._user = user
        self.save_called = False

    def find_by_username(self, username: str) -> User | None:
        return self._user

    def find_by_id(self, user_id: str) -> User | None:
        return self._user

    def save(self, user: User) -> None:
        self.save_called = True

    def exists_by_username(self, username: str) -> bool:
        return self._user is not None and self._user.username == username

    def exists_by_email(self, email: str) -> bool:
        return self._user is not None and self._user.email == email

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return [self._user] if self._user else []

    def count(self) -> int:
        return 1 if self._user else 0

    def count_by_role(self, role: Role) -> int:
        return 1 if self._user and role == Role.ADMIN else 0

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


class FakeLockoutRepository(LockoutRepository):
    def __init__(self) -> None:
        self._lockouts: dict[str, AccountLockout] = {}

    def get(self, user_id: str) -> AccountLockout | None:
        return self._lockouts.get(user_id)

    def save(self, lockout: AccountLockout) -> None:
        self._lockouts[lockout.user_id] = lockout

    def delete(self, user_id: str) -> None:
        self._lockouts.pop(user_id, None)


class FakeClock(ClockPort):
    def __init__(self, now: float = 1000.0) -> None:
        self._now = now

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


_DEFAULT_LOCKOUT_POLICY = LockoutPolicy(max_attempts=5, lockout_duration_seconds=900)


def _make_login(
    repo: UserRepository,
    hasher: PasswordHasher,
    tokens: TokenService,
    lockout_repo: LockoutRepository | None = None,
    clock: ClockPort | None = None,
    policy: LockoutPolicy | None = None,
) -> Login:
    return Login(
        repo,
        hasher,
        tokens,
        lockout_repo if lockout_repo is not None else FakeLockoutRepository(),
        clock if clock is not None else FakeClock(),
        policy if policy is not None else _DEFAULT_LOCKOUT_POLICY,
    )


def _make_user(**kwargs) -> User:
    defaults = dict(
        id="user-001",
        username="testuser",
        email="test@example.com",
        password_hash="hashed:password",
        role=Role.VIEWER,
    )
    defaults.update(kwargs)
    return User(**defaults)


# --- Tests --------------------------------------------------------------------


class TestLogin:
    def test_successful_login(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        tokens = StubTokenService()

        login = _make_login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="password")
        result = login.execute(request)

        assert result.user_id == "user-001"
        assert result.username == "testuser"
        assert result.access_token == "access-token-user-001"
        assert result.refresh_token == "refresh-token-user-001"
        assert tokens.create_access_called is True
        assert tokens.create_refresh_called is True
        assert repo.save_called is True

    def test_login_records_last_login(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        tokens = StubTokenService()

        login = _make_login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="password")
        login.execute(request)

        assert repo.save_called is True

    def test_login_with_wrong_password(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=False)
        tokens = StubTokenService()

        login = _make_login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="wrong")

        with pytest.raises(AuthenticationError, match="invalid username or password"):
            login.execute(request)

    def test_login_with_nonexistent_user(self) -> None:
        repo = StubUserRepository(user=None)
        hasher = StubPasswordHasher()
        tokens = StubTokenService()

        login = _make_login(repo, hasher, tokens)
        request = LoginRequest(username="nobody", password="password")

        with pytest.raises(AuthenticationError, match="invalid username or password"):
            login.execute(request)

    def test_login_with_disabled_account(self) -> None:
        user = _make_user(is_active=False)
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        tokens = StubTokenService()

        login = _make_login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="password")

        with pytest.raises(AuthenticationError, match="disabled"):
            login.execute(request)


class TestAccountLockout:
    def test_locks_after_max_attempts_and_rejects_even_correct_password(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        tokens = StubTokenService()
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        policy = LockoutPolicy(max_attempts=3, lockout_duration_seconds=900)

        wrong_hasher = StubPasswordHasher(verify_result=False)
        login = _make_login(repo, wrong_hasher, tokens, lockout_repo, clock, policy)
        request = LoginRequest(username="testuser", password="wrong")

        for _ in range(3):
            with pytest.raises(AuthenticationError):
                login.execute(request)

        # The 4th attempt is against an already-locked account. Use a hasher
        # that reports the CORRECT password this time - it must still fail,
        # proving lockout wins over a correct password, not just over wrong ones.
        correct_hasher = StubPasswordHasher(verify_result=True)
        login_with_correct_password = _make_login(repo, correct_hasher, tokens, lockout_repo, clock, policy)
        correct_request = LoginRequest(username="testuser", password="password")

        with pytest.raises(AuthenticationError, match="invalid username or password"):
            login_with_correct_password.execute(correct_request)
        assert tokens.create_access_called is False

    def test_locked_account_error_is_identical_to_wrong_password_error(self) -> None:
        # Same account, same policy, same clock - one login locked by prior
        # failures, one fresh. Both must raise the exact same message.
        locked_user = _make_user(id="user-locked", username="lockeduser")
        fresh_user = _make_user(id="user-fresh", username="freshuser")
        tokens = StubTokenService()
        clock = FakeClock()
        policy = LockoutPolicy(max_attempts=1, lockout_duration_seconds=900)

        locked_repo = StubUserRepository(locked_user)
        locked_lockout_repo = FakeLockoutRepository()
        wrong_hasher = StubPasswordHasher(verify_result=False)
        lock_it = _make_login(locked_repo, wrong_hasher, tokens, locked_lockout_repo, clock, policy)
        with pytest.raises(AuthenticationError):
            lock_it.execute(LoginRequest(username="lockeduser", password="wrong"))

        # Now locked. Try again with a hasher that would report success.
        correct_hasher = StubPasswordHasher(verify_result=True)
        try_locked = _make_login(locked_repo, correct_hasher, tokens, locked_lockout_repo, clock, policy)
        locked_error = None
        try:
            try_locked.execute(LoginRequest(username="lockeduser", password="password"))
        except AuthenticationError as exc:
            locked_error = str(exc)

        fresh_repo = StubUserRepository(fresh_user)
        wrong_hasher_2 = StubPasswordHasher(verify_result=False)
        try_fresh = _make_login(fresh_repo, wrong_hasher_2, tokens, FakeLockoutRepository(), clock, policy)
        fresh_error = None
        try:
            try_fresh.execute(LoginRequest(username="freshuser", password="wrong"))
        except AuthenticationError as exc:
            fresh_error = str(exc)

        assert locked_error is not None
        assert fresh_error is not None
        assert locked_error == fresh_error == "invalid username or password"

    def test_nonexistent_account_and_locked_account_produce_indistinguishable_responses(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        tokens = StubTokenService()
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        policy = LockoutPolicy(max_attempts=1, lockout_duration_seconds=900)

        wrong_hasher = StubPasswordHasher(verify_result=False)
        lock_it = _make_login(repo, wrong_hasher, tokens, lockout_repo, clock, policy)
        with pytest.raises(AuthenticationError):
            lock_it.execute(LoginRequest(username="testuser", password="wrong"))

        # Locked-account attempt.
        locked_login = _make_login(repo, StubPasswordHasher(verify_result=True), tokens, lockout_repo, clock, policy)
        locked_error = None
        try:
            locked_login.execute(LoginRequest(username="testuser", password="anything"))
        except AuthenticationError as exc:
            locked_error = str(exc)

        # Nonexistent-account attempt (separate repo/lockout store, same policy/clock).
        nonexistent_login = _make_login(
            StubUserRepository(user=None), StubPasswordHasher(), tokens, FakeLockoutRepository(), clock, policy
        )
        nonexistent_error = None
        try:
            nonexistent_login.execute(LoginRequest(username="nobody", password="anything"))
        except AuthenticationError as exc:
            nonexistent_error = str(exc)

        assert locked_error == nonexistent_error == "invalid username or password"

    def test_hasher_verify_still_called_when_already_locked(self) -> None:
        """Timing-safety: the real hash comparison must run even when the
        account is already locked, so a locked account's response takes the
        same time as an ordinary wrong-password check - matching the
        dummy-hash pattern's care level for the nonexistent-user case."""
        user = _make_user()
        repo = StubUserRepository(user)
        tokens = StubTokenService()
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        policy = LockoutPolicy(max_attempts=1, lockout_duration_seconds=900)

        wrong_hasher = StubPasswordHasher(verify_result=False)
        lock_it = _make_login(repo, wrong_hasher, tokens, lockout_repo, clock, policy)
        with pytest.raises(AuthenticationError):
            lock_it.execute(LoginRequest(username="testuser", password="wrong"))

        hasher_while_locked = StubPasswordHasher(verify_result=True)
        try_while_locked = _make_login(repo, hasher_while_locked, tokens, lockout_repo, clock, policy)
        with pytest.raises(AuthenticationError):
            try_while_locked.execute(LoginRequest(username="testuser", password="password"))

        assert hasher_while_locked.verify_called is True

    def test_lockout_clears_after_configured_duration(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        tokens = StubTokenService()
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        policy = LockoutPolicy(max_attempts=1, lockout_duration_seconds=900)

        wrong_hasher = StubPasswordHasher(verify_result=False)
        lock_it = _make_login(repo, wrong_hasher, tokens, lockout_repo, clock, policy)
        with pytest.raises(AuthenticationError):
            lock_it.execute(LoginRequest(username="testuser", password="wrong"))

        clock.advance(901)  # past the 900s lockout duration

        correct_hasher = StubPasswordHasher(verify_result=True)
        login_after_expiry = _make_login(repo, correct_hasher, tokens, lockout_repo, clock, policy)
        result = login_after_expiry.execute(LoginRequest(username="testuser", password="password"))

        assert result.user_id == user.id

    def test_successful_login_resets_failed_attempt_count(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        tokens = StubTokenService()
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        policy = LockoutPolicy(max_attempts=3, lockout_duration_seconds=900)

        # Two failures, then a successful login.
        wrong_hasher = StubPasswordHasher(verify_result=False)
        fail_login = _make_login(repo, wrong_hasher, tokens, lockout_repo, clock, policy)
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                fail_login.execute(LoginRequest(username="testuser", password="wrong"))

        correct_hasher = StubPasswordHasher(verify_result=True)
        succeed_login = _make_login(repo, correct_hasher, tokens, lockout_repo, clock, policy)
        succeed_login.execute(LoginRequest(username="testuser", password="password"))

        # Two more failures after the reset should NOT lock (would need 3
        # under this policy) - proving the count restarted from zero rather
        # than continuing at 2.
        fail_again = _make_login(repo, wrong_hasher, tokens, lockout_repo, clock, policy)
        for _ in range(2):
            with pytest.raises(AuthenticationError, match="invalid username or password"):
                fail_again.execute(LoginRequest(username="testuser", password="wrong"))

        final_correct_login = _make_login(repo, correct_hasher, tokens, lockout_repo, clock, policy)
        result = final_correct_login.execute(LoginRequest(username="testuser", password="password"))
        assert result.user_id == user.id
