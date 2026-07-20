from __future__ import annotations

from kingsec.domain.rate_limit import (
    AccountLockout,
    LockoutPolicy,
    RateLimitBucket,
    RateLimitDecision,
    RateLimitExceeded,
    RateLimitGroup,
    RateLimitKeyType,
    RateLimitPolicy,
)


class TestRateLimitPolicy:
    def test_default_key_type_is_ip(self) -> None:
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=900,
        )
        assert policy.key_type == RateLimitKeyType.IP

    def test_all_groups_have_unique_values(self) -> None:
        values = {g.value for g in RateLimitGroup}
        assert len(values) == len(RateLimitGroup)

    def test_all_key_types_have_unique_values(self) -> None:
        values = {k.value for k in RateLimitKeyType}
        assert len(values) == len(RateLimitKeyType)

    def test_frozen_policy(self) -> None:
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=900,
        )
        try:
            policy.max_requests = 10
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestRateLimitBucket:
    def test_frozen_bucket(self) -> None:
        bucket = RateLimitBucket(
            key="test",
            max_requests=5,
            window_seconds=900,
            window_start=100.0,
            count=1,
        )
        try:
            bucket.count = 2
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestRateLimitDecision:
    def test_frozen_decision(self) -> None:
        d = RateLimitDecision(allowed=True, limit=5, remaining=4, reset_seconds=10)
        try:
            d.allowed = False
            assert False, "should be frozen"
        except AttributeError:
            pass

    def test_allowed_decision(self) -> None:
        d = RateLimitDecision(allowed=True, limit=10, remaining=9, reset_seconds=0)
        assert d.allowed
        assert d.limit == 10
        assert d.remaining == 9
        assert d.reset_seconds == 0

    def test_denied_decision(self) -> None:
        d = RateLimitDecision(allowed=False, limit=5, remaining=0, reset_seconds=45)
        assert not d.allowed
        assert d.remaining == 0
        assert d.reset_seconds == 45


class TestRateLimitExceeded:
    def test_carries_decision(self) -> None:
        decision = RateLimitDecision(
            allowed=False, limit=5, remaining=0, reset_seconds=60
        )
        exc = RateLimitExceeded(decision)
        assert exc.decision == decision
        assert str(exc) == "rate limit exceeded"

    def test_is_exception(self) -> None:
        decision = RateLimitDecision(
            allowed=False, limit=5, remaining=0, reset_seconds=60
        )
        exc = RateLimitExceeded(decision)
        assert isinstance(exc, Exception)


class TestLockoutPolicy:
    def test_frozen_lockout_policy(self) -> None:
        policy = LockoutPolicy(max_attempts=5, lockout_duration_seconds=900)
        try:
            policy.max_attempts = 10
            assert False, "should be frozen"
        except AttributeError:
            pass

    def test_default_values(self) -> None:
        policy = LockoutPolicy(max_attempts=5, lockout_duration_seconds=900)
        assert policy.max_attempts == 5
        assert policy.lockout_duration_seconds == 900


class TestAccountLockout:
    def test_frozen_account_lockout(self) -> None:
        lockout = AccountLockout(user_id="u1", locked_until=1000.0, failed_attempts=3)
        try:
            lockout.failed_attempts = 4
            assert False, "should be frozen"
        except AttributeError:
            pass

    def test_holds_user_data(self) -> None:
        lockout = AccountLockout(user_id="u1", locked_until=2000.0, failed_attempts=5)
        assert lockout.user_id == "u1"
        assert lockout.locked_until == 2000.0
        assert lockout.failed_attempts == 5
