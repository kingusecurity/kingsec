"""Port for schedule-occurrence persistence — no infrastructure imports.

See ``application/schedule_occurrence.py`` for the state machine this port
enforces atomically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.application.schedule_occurrence import ScheduleOccurrence


class ScheduleOccurrenceRepositoryPort(ABC):
    @abstractmethod
    def try_claim(self, schedule_id: str, occurrence_key: str) -> ScheduleOccurrence:
        """Atomically create the occurrence row if it doesn't exist yet.

        Implemented as ``INSERT ... ON CONFLICT(schedule_id, occurrence_key)
        DO NOTHING`` followed by a read of whichever row now exists, inside
        one transaction - so this always returns the current, authoritative
        state of the occurrence, whether this call created it (fresh,
        ``CLAIMED``, version 1) or a prior call already did (any status).

        This method never signals "already claimed" as a return value vs.
        "claimed just now" - the caller distinguishes those by inspecting
        the returned ``ScheduleOccurrence.status``/``version``/
        ``claimed_at``. A genuine database failure (connection lost, disk
        full, etc.) propagates as an exception - it must never be
        interpreted as "already claimed".
        """
        ...

    @abstractmethod
    def try_begin_creation(self, occurrence_id: str, expected_version: int) -> int | None:
        """Atomically reserve the exclusive right to attempt
        ``CreateAssessment`` for this occurrence.

        A single conditional ``UPDATE ... WHERE id = ? AND version = ? AND
        status = 'CLAIMED'`` advancing status to ``CREATING`` (not merely
        bumping version - see the module docstring in
        ``schedule_occurrence.py`` for the ABA race this closes). Returns
        the new version if this call won, or ``None`` if it lost (another
        caller already advanced it, or the occurrence is no longer
        ``CLAIMED``) - in which case the caller MUST NOT call
        ``CreateAssessment``.
        """
        ...

    @abstractmethod
    def mark_assessment_created(self, occurrence_id: str, expected_version: int, assessment_id: str) -> bool:
        """Atomically record that ``CreateAssessment`` succeeded.

        Conditional ``UPDATE ... WHERE id = ? AND version = ? AND status =
        'CREATING'`` advancing to ``ASSESSMENT_CREATED`` and storing
        ``assessment_id``. ``expected_version`` must be the version
        returned by the paired ``try_begin_creation()`` call. Returns
        whether the write matched (it always should, since the caller
        exclusively holds that version from ``try_begin_creation()`` -
        false would indicate a logic error, not a normal race outcome).
        """
        ...

    @abstractmethod
    def revert_to_claimed(self, occurrence_id: str, expected_version: int) -> bool:
        """Atomically revert ``CREATING`` back to ``CLAIMED`` after a
        caught ``CreateAssessment`` failure, making the occurrence safely
        retryable by a later call instead of stuck forever (Case A).

        Conditional ``UPDATE ... WHERE id = ? AND version = ? AND status =
        'CREATING'``. Not reached on an uncaught process crash between
        ``try_begin_creation()`` and this call - that residual gap
        requires a future lease/timeout mechanism, out of scope here.
        """
        ...

    @abstractmethod
    def try_begin_submission(self, occurrence_id: str, expected_version: int) -> int | None:
        """Same pattern as ``try_begin_creation()``, gated on status ==
        ``ASSESSMENT_CREATED`` instead of ``CLAIMED``, advancing to
        ``SUBMITTING`` - reserves the exclusive right to attempt
        ``SubmitAssessment``.
        """
        ...

    @abstractmethod
    def mark_submitted(self, occurrence_id: str, expected_version: int) -> bool:
        """Atomically record that ``SubmitAssessment`` succeeded -
        ``UPDATE ... WHERE status = 'SUBMITTING'`` advancing to
        ``SUBMITTED``, the occurrence's terminal, safe-forever state.
        """
        ...

    @abstractmethod
    def revert_to_assessment_created(self, occurrence_id: str, expected_version: int) -> bool:
        """Atomically revert ``SUBMITTING`` back to ``ASSESSMENT_CREATED``
        after a caught ``SubmitAssessment`` failure (Case B) - a later
        retry resumes submission on the same assessment, never calling
        ``CreateAssessment`` again. Same uncaught-crash caveat as
        ``revert_to_claimed()``.
        """
        ...
