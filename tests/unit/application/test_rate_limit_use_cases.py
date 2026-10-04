from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.application.use_cases.check_account_lockout import CheckAccountLockout
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.application.use_cases.rate_limit_dto import (
    CheckAccountLockoutRequest,
    CheckRateLimitRequest,
    RecordFailedAuthenticationRequest,
    RecordSuccessfulAuthenticationRequest,
    ResetFailedAttemptsRequest,
)
from kingsec.application.use_cases.record_failed_authentication import (
    RecordFailedAuthentication,
)
from kingsec.application.use_cases.record_successful_authentication import (
    RecordSuccessfulAuthentication,
)
from kingsec.application.use_cases.reset_failed_attempts import ResetFailedAttempts
from kingsec.domain.rate_limit import (
    AccountLockout,
    RateLimitDecision,
    RateLimitExceeded,
    RateLimitGroup,
    RateLimitPolicy,
)


@dataclass
class FakeRateLimiter(RateLimiterPort):
    decisions: dict[str, RateLimitDecision] = field(default_factory=dict)
    records: list[tuple[str, RateLimitPolicy]] = field(default_factory=list)
    resets: list[str] = field(default_factory=list)

    def check(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        return self.decisions.get(
            key,
            RateLimitDecision(
                allowed=True,
                limit=policy.max_requests,
                remaining=policy.max_requests,
                reset_seconds=0,
            ),
        )

    def record(self, key: str, policy: RateLimitPolicy) -> None:
        self.records.append((key, policy))

    def reset(self, key: str) -> None:
        self.resets.append(key)


@dataclass
class FakeLockoutRepository(LockoutRepository):
    lockouts: dict[str, AccountLockout] = field(default_factory=dict)

    def get(self, user_id: str) -> AccountLockout | None:
        return self.lockouts.get(user_id)

    def save(self, lockout: AccountLockout) -> None:
        self.lockouts[lockout.user_id] = lockout

    def delete(self, user_id: str) -> None:
        self.lockouts.pop(user_id, None)


@dataclass
class FakeClock(ClockPort):
    _now: float = 1000.0

    def now(self) -> float:
        return self._now


class TestCheckRateLimit:
    def test_allows_within_limit(self) -> None:
        limiter = FakeRateLimiter()
        use_case = CheckRateLimit(limiter)
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=900,
        )
        req = CheckRateLimitRequest(key="ip:1.2.3.4", policy=policy)
        result = use_case.execute(req)
        assert result.allowed
        assert result.limit == 5
        assert result.remaining == 5
        assert len(limiter.records) == 1

    def test_raises_when_exceeded(self) -> None:
        limiter = FakeRateLimiter()
        limiter.decisions["ip:1.2.3.4"] = RateLimitDecision(
            allowed=False,
            limit=5,
            remaining=0,
            reset_seconds=120,
        )
        use_case = CheckRateLimit(limiter)
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=900,
        )
        req = CheckRateLimitRequest(key="ip:1.2.3.4", policy=policy)
        with pytest.raises(RateLimitExceeded) as exc_info:
            use_case.execute(req)
        assert exc_info.value.decision.remaining == 0
        assert exc_info.value.decision.reset_seconds == 120

    def test_does_not_record_when_exceeded(self) -> None:
        limiter = FakeRateLimiter()
        limiter.decisions["ip:1.2.3.4"] = RateLimitDecision(
            allowed=False,
            limit=5,
            remaining=0,
            reset_seconds=60,
        )
        use_case = CheckRateLimit(limiter)
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=900,
        )
        req = CheckRateLimitRequest(key="ip:1.2.3.4", policy=policy)
        with pytest.raises(RateLimitExceeded):
            use_case.execute(req)
        assert len(limiter.records) == 0


class TestRecordFailedAuthentication:
    def test_records_first_failure(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        use_case = RecordFailedAuthentication(lockout_repo, clock, max_attempts=3)
        req = RecordFailedAuthenticationRequest(user_id="u1", ip_address="1.2.3.4", username="alice")
        result = use_case.execute(req)
        assert not result.locked
        assert result.failed_attempts == 1
        assert result.locked_until is None

    def test_locks_after_max_attempts(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        use_case = RecordFailedAuthentication(lockout_repo, clock, max_attempts=3, lockout_duration_seconds=900)
        req = RecordFailedAuthenticationRequest(user_id="u2", ip_address="1.2.3.4", username="bob")
        for _ in range(2):
            use_case.execute(req)
        result = use_case.execute(req)
        assert result.locked
        assert result.failed_attempts == 3
        assert result.locked_until is not None
        assert result.locked_until == 1000.0 + 900.0

    def test_rejects_when_already_locked(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        lockout_repo.save(AccountLockout(user_id="u3", locked_until=2000.0, failed_attempts=5))
        use_case = RecordFailedAuthentication(lockout_repo, clock, max_attempts=3, lockout_duration_seconds=900)
        req = RecordFailedAuthenticationRequest(user_id="u3", ip_address="1.2.3.4", username="charlie")
        result = use_case.execute(req)
        assert result.locked
        # failed_attempts should not have increased
        assert result.failed_attempts == 5

    def test_increments_after_lock_expired(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock(_now=1000.0)
        lockout_repo.save(AccountLockout(user_id="u4", locked_until=500.0, failed_attempts=3))
        use_case = RecordFailedAuthentication(lockout_repo, clock, max_attempts=3, lockout_duration_seconds=900)
        req = RecordFailedAuthenticationRequest(user_id="u4", ip_address="1.2.3.4", username="dave")
        result = use_case.execute(req)
        # Lock expired (500 < 1000), so it increments: 3 + 1 = 4
        assert result.locked  # 4 >= 3 so locked again
        assert result.failed_attempts == 4

    def test_live_lockout_duration_is_fixed_not_progressive(self) -> None:
        """Phase 3 (auth hardening), Q5's definitive answer: this
        documents CURRENT behavior on the live login path, NOT a desired
        invariant. AccountLockout (domain/rate_limit.py) has exactly three
        fields - user_id, locked_until, failed_attempts - and none of them
        record how many times this account has been locked before.
        RecordFailedAuthentication.execute() always computes
        locked_until = now + lockout_duration_seconds, the same fixed
        value every time, forever - unlike the separate, never-wired
        AccountLockoutService (deleted this phase), which escalated
        60s/120s/300s/600s across repeated lockouts. This is not a bug to
        fix here (see docs/STATUS.md's own decision record) - a fixed
        900s lockout is a defensible, shippable control.

        If progressive escalation is EVER implemented on this path (see
        docs/STATUS.md's backlog entry naming what it would need - a
        persisted lockout-count/tier field, a migration, a tiering
        policy, a decay rule), THIS TEST MUST BE REPLACED, NOT DELETED:
        a fixed duration would then be the wrong behavior, not merely an
        undesired one, and something needs to keep proving whatever the
        new, real invariant is.
        """
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock(_now=1000.0)
        use_case = RecordFailedAuthentication(lockout_repo, clock, max_attempts=1, lockout_duration_seconds=900)
        req = RecordFailedAuthenticationRequest(user_id="u5", ip_address="1.2.3.4", username="eve")

        # First lockout episode.
        first = use_case.execute(req)
        assert first.locked
        assert first.locked_until is not None
        first_duration = first.locked_until - clock.now()
        assert first_duration == 900.0

        # Let the lock naturally expire, then lock the SAME account again -
        # a second, independent episode with a higher failed_attempts count.
        clock._now = first.locked_until + 1.0
        second = use_case.execute(req)
        assert second.locked
        assert second.locked_until is not None
        assert second.failed_attempts > first.failed_attempts
        second_duration = second.locked_until - clock.now()

        assert second_duration == first_duration == 900.0, (
            "the live lockout path escalated duration across repeated lockouts - "
            "if this is intentional, REPLACE this test, don't just delete it "
            "(see docs/STATUS.md's lockout-escalation backlog entry)"
        )


class TestRecordSuccessfulAuthentication:
    def test_resets_failed_attempts(self) -> None:
        lockout_repo = FakeLockoutRepository()
        lockout_repo.save(AccountLockout(user_id="u1", locked_until=2000.0, failed_attempts=5))
        use_case = RecordSuccessfulAuthentication(lockout_repo)
        req = RecordSuccessfulAuthenticationRequest(user_id="u1")
        result = use_case.execute(req)
        assert result.previous_failed_attempts == 5
        assert lockout_repo.get("u1") is None

    def test_no_failures(self) -> None:
        lockout_repo = FakeLockoutRepository()
        use_case = RecordSuccessfulAuthentication(lockout_repo)
        req = RecordSuccessfulAuthenticationRequest(user_id="u2")
        result = use_case.execute(req)
        assert result.previous_failed_attempts == 0


class TestCheckAccountLockout:
    def test_not_locked(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock()
        use_case = CheckAccountLockout(lockout_repo, clock)
        req = CheckAccountLockoutRequest(user_id="u1")
        result = use_case.execute(req)
        assert not result.locked
        assert result.failed_attempts == 0

    def test_locked(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock(_now=1000.0)
        lockout_repo.save(AccountLockout(user_id="u1", locked_until=2000.0, failed_attempts=5))
        use_case = CheckAccountLockout(lockout_repo, clock)
        req = CheckAccountLockoutRequest(user_id="u1")
        result = use_case.execute(req)
        assert result.locked
        assert result.failed_attempts == 5
        assert result.locked_until == 2000.0

    def test_auto_unlock_after_expiry(self) -> None:
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock(_now=1000.0)
        lockout_repo.save(AccountLockout(user_id="u1", locked_until=500.0, failed_attempts=5))
        use_case = CheckAccountLockout(lockout_repo, clock)
        req = CheckAccountLockoutRequest(user_id="u1")
        result = use_case.execute(req)
        assert not result.locked
        assert result.failed_attempts == 0
        assert lockout_repo.get("u1") is None

    def test_in_progress_attempt_count_is_not_locked_and_is_not_cleared(self) -> None:
        """RecordFailedAuthentication saves locked_until=0.0 for an attempt
        that hasn't crossed the lockout threshold yet - that's not an
        expired lock, so checking it must neither report locked=True nor
        delete the record (which would silently reset the attempt count on
        every check before the threshold is ever reached)."""
        lockout_repo = FakeLockoutRepository()
        clock = FakeClock(_now=1000.0)
        lockout_repo.save(AccountLockout(user_id="u1", locked_until=0.0, failed_attempts=2))
        use_case = CheckAccountLockout(lockout_repo, clock)
        req = CheckAccountLockoutRequest(user_id="u1")
        result = use_case.execute(req)
        assert not result.locked
        assert result.failed_attempts == 2
        assert lockout_repo.get("u1") is not None


class TestResetFailedAttempts:
    def test_resets_lockout(self) -> None:
        lockout_repo = FakeLockoutRepository()
        lockout_repo.save(AccountLockout(user_id="u1", locked_until=2000.0, failed_attempts=5))
        use_case = ResetFailedAttempts(lockout_repo)
        req = ResetFailedAttemptsRequest(user_id="u1")
        result = use_case.execute(req)
        assert result.success
        assert lockout_repo.get("u1") is None

    def test_reset_nonexistent(self) -> None:
        lockout_repo = FakeLockoutRepository()
        use_case = ResetFailedAttempts(lockout_repo)
        req = ResetFailedAttemptsRequest(user_id="u2")
        result = use_case.execute(req)
        assert result.success
