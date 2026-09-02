"""Port for schedule persistence — no infrastructure imports."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.schedule import ScanSchedule


class ScheduleRepositoryPort(ABC):
    @abstractmethod
    def save(self, schedule: ScanSchedule) -> None: ...

    @abstractmethod
    def find_by_id(self, schedule_id: str) -> ScanSchedule | None: ...

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> list[ScanSchedule]: ...

    @abstractmethod
    def find_all(self) -> list[ScanSchedule]: ...

    @abstractmethod
    def find_due(self, now_utc_str: str) -> list[ScanSchedule]: ...

    @abstractmethod
    def try_claim(self, schedule: ScanSchedule) -> ScanSchedule | None:
        """Atomically claim a due schedule for execution before job
        submission (KSEC-93-05).

        Must perform the version check and the claiming write as a
        single atomic conditional UPDATE - the same idiom already used by
        ``save()``'s optimistic lock and Phase 87's
        ``AssessmentConcurrencyPort.try_reserve_slot()`` - so two callers
        racing the same schedule (e.g. two ``InProcessScheduler``
        instances sharing one database) can never both win: only one
        UPDATE actually matches the row, the other affects zero rows.

        The WHERE clause must re-check liveness (not tombstoned) and
        due-eligibility (enabled, not paused) at claim time, not only at
        the earlier ``find_due()`` read - closing the window where the
        schedule could have been deleted, paused, or otherwise modified
        between the read and this call. A version mismatch from *any*
        such change causes the claim to fail exactly like a losing race.

        Args:
            schedule: The schedule as read by ``find_due()`` (or another
                caller), carrying the version it was read at.

        Returns:
            An updated copy of ``schedule`` with the post-claim version,
            if this call won the claim. ``None`` if it lost - the row's
            version didn't match (already claimed, modified, paused, or
            tombstoned by someone else since the read) - in which case
            the caller MUST NOT proceed to submit a job for it.
        """
        ...

    @abstractmethod
    def delete(self, schedule_id: str) -> None: ...
