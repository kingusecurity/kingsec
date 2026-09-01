"""Port for atomic, cross-process assessment concurrency-slot reservation.

KSEC-87-02: `max_concurrent_assessments` existed as configuration but was
never enforced anywhere. A naive "count running, then start if under the
limit" check is explicitly unsafe - two concurrent requests can both
observe capacity and both start, recreating the exact TOCTOU class Phases
85/86 closed for schedules/organizations/teams. This port exists so the
check-and-claim happens as a SINGLE atomic database statement instead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class AssessmentConcurrencyPort(ABC):
    @abstractmethod
    def try_reserve_slot(self, max_concurrent: int) -> bool:
        """Atomically claim one concurrency slot if capacity allows.

        Implementations MUST perform the capacity check and the claim as a
        single atomic operation (e.g. one conditional ``UPDATE``) - never a
        separate "read the count" step followed by a later "write" step,
        which would reopen the TOCTOU window this port exists to close.

        Args:
            max_concurrent: The configured maximum number of concurrently
                reserved slots.

        Returns:
            ``True`` if a slot was claimed (the caller now owns it and
            MUST call ``release_slot()`` exactly once when done, success
            or failure). ``False`` if capacity was already exhausted (no
            slot was claimed - nothing to release).
        """
        ...

    @abstractmethod
    def release_slot(self) -> None:
        """Release one previously-claimed concurrency slot.

        Must be safe to call from a ``finally`` block. Must never allow
        the active count to go negative (a defensive floor at zero),
        since a bug that calls this without a matching successful
        ``try_reserve_slot()`` must not permanently corrupt capacity for
        every future caller.
        """
        ...
