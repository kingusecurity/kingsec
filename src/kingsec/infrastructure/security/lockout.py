"""Account lockout protection for authentication endpoints.

Tracks failed login attempts per username and locks out accounts that
exceed the maximum number of failures within a time window. Lockout
state is in-memory (single-process). For multi-process deployments,
swap the store for Redis.

Design decisions:
    - Lockout is per-username (not per-IP) to prevent credential stuffing
      across distributed IPs.
    - Failed attempts from different IPs still count toward the same
      username's lockout threshold.
    - Lockout duration increases with repeated lockouts (progressive delay).
    - Lockout events are logged for audit purposes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from kingsec.infrastructure.logging import get_logger

logger = get_logger("kingsec.security.lockout")


@dataclass
class _AttemptRecord:
    """Tracks failed attempts for a single username."""

    failures: list[float] = field(default_factory=list)
    lockout_until: float = 0.0
    lockout_count: int = 0

    def record_failure(self, now: float, threshold: int, window_seconds: int) -> None:
        """Record a failed attempt and apply lockout if threshold exceeded."""
        # Purge expired failures outside the window.
        cutoff = now - window_seconds
        self.failures = [t for t in self.failures if t > cutoff]
        self.failures.append(now)

        if len(self.failures) >= threshold and now >= self.lockout_until:
            self.lockout_count += 1
            # Progressive delay: 60s, 120s, 300s, 600s (caps at 10 min).
            delays = [60, 120, 300, 600]
            delay = delays[min(self.lockout_count - 1, len(delays) - 1)]
            self.lockout_until = now + delay
            logger.warning(
                "account locked out: username failures=%d lockout_count=%d delay=%ds",
                len(self.failures),
                self.lockout_count,
                delay,
            )

    def is_locked_out(self, now: float) -> bool:
        return now < self.lockout_until

    @property
    def retry_after(self) -> float:
        return max(0.0, self.lockout_until - time.monotonic())

    def clear(self) -> None:
        """Successful login — reset all failure state."""
        self.failures.clear()
        self.lockout_until = 0.0
        self.lockout_count = 0


class AccountLockoutService:
    """In-memory account lockout tracker.

    Usage::

        lockout = AccountLockoutService(max_failures=5, lockout_window=900)

        if lockout.is_locked_out("alice"):
            raise TooManyAttempts(lockout.retry_after("alice"))

        # ... attempt auth ...

        if auth_failed:
            lockout.record_failure("alice")
        elif auth_succeeded:
            lockout.clear("alice")
    """

    def __init__(
        self,
        max_failures: int = 5,
        lockout_window: int = 900,
        eviction_interval: int = 500,
    ) -> None:
        self._max_failures = max_failures
        self._lockout_window = lockout_window
        self._eviction_interval = eviction_interval
        self._records: dict[str, _AttemptRecord] = {}
        self._lock = threading.Lock()
        self._dispatch_count = 0

    def is_locked_out(self, username: str) -> bool:
        """Check if the given username is currently locked out."""
        with self._lock:
            record = self._records.get(username)
            if record is None:
                return False
            return record.is_locked_out(time.monotonic())

    def retry_after(self, username: str) -> float:
        """Return seconds until the lockout expires for *username*."""
        with self._lock:
            record = self._records.get(username)
            if record is None:
                return 0.0
            return record.retry_after

    def record_failure(self, username: str) -> None:
        """Record a failed authentication attempt for *username*."""
        with self._lock:
            record = self._records.setdefault(username, _AttemptRecord())
            record.record_failure(
                time.monotonic(), self._max_failures, self._lockout_window
            )
            self._dispatch_count += 1
            if self._dispatch_count >= self._eviction_interval:
                self._evict()

    def clear(self, username: str) -> None:
        """Clear lockout state after a successful login."""
        with self._lock:
            record = self._records.get(username)
            if record is not None:
                record.clear()

    def _evict(self) -> None:
        """Remove records that are no longer locked out and have no recent failures."""
        self._dispatch_count = 0
        now = time.monotonic()
        cutoff = now - self._lockout_window
        to_remove = [
            username
            for username, record in self._records.items()
            if not record.is_locked_out(now)
            and not any(t > cutoff for t in record.failures)
        ]
        for username in to_remove:
            del self._records[username]
        if to_remove:
            logger.debug("evicted %d expired lockout records", len(to_remove))
