"""ScheduleOccurrence: the durable record of one specific scheduled firing.

KSEC-98-01: a schedule's own atomic claim (``ScheduleRepositoryPort.try_claim()``,
Phase 93) guarantees only one scheduler *instance* processes a given due
schedule at a time. It does not, and structurally cannot, guarantee that the
same logical occurrence (this schedule's *next_run* being fulfilled) is never
processed twice - a submission can succeed while the schedule's own
finalization write fails, leaving the schedule due again and letting a later
poll cycle re-process the identical occurrence (Phase 94/96).

A ``ScheduleOccurrence`` closes that gap as a second, independent layer: its
identity is ``(schedule_id, occurrence_key)``, enforced unique by the database
itself (see ``ScheduleOccurrenceRepositoryPort``), not by an in-memory check.

State machine - five states, two of them transient mutexes (see
``submit_scheduled_assessment.py`` for the exact call sequence):

    CLAIMED             -- occurrence reserved, no assessment yet
        --> CREATING             (won the exclusive right to attempt
                                   CreateAssessment - see below for why
                                   this is a real status, not just a
                                   version bump)
    CREATING            -- exactly one caller is attempting CreateAssessment
        --> ASSESSMENT_CREATED   (CreateAssessment succeeded)
        --> CLAIMED              (CreateAssessment failed - safe to retry
                                   from CLAIMED again)
    ASSESSMENT_CREATED  -- a real assessment exists, not yet submitted
        --> SUBMITTING            (won the exclusive right to attempt
                                    SubmitAssessment)
    SUBMITTING          -- exactly one caller is attempting SubmitAssessment
        --> SUBMITTED             (SubmitAssessment succeeded)
        --> ASSESSMENT_CREATED    (SubmitAssessment failed - safe to
                                    retry, resuming from the existing
                                    assessment, never calling
                                    CreateAssessment again)
    SUBMITTED           -- terminal; the occurrence is fully, safely done

Why CREATING/SUBMITTING must be real statuses, not merely a version bump
under an unchanged status (KSEC-98-01, found by
test_scheduled_assessment_concurrency.py): if "reserving the right to
create" only bumped ``version`` while leaving ``status='CLAIMED'``, a
SECOND caller that independently re-reads the row *after* the first
caller's version bump but *before* the first caller finishes
CreateAssessment would see a fresh version with status still ``CLAIMED``
and could pass the identical ``status == 'CLAIMED'`` gate again - an ABA
race that let two callers both create a real assessment for the same
occurrence. Requiring the WHERE clause to also match the OLD status
(``CLAIMED``) and moving to a status no later reader can mistake for
"still available" (``CREATING``) closes this: any caller reading the row
while creation is in flight sees ``CREATING``, not ``CLAIMED``, and
correctly does nothing.

``version`` is the same optimistic-lock idiom already used by
``ScheduleORM``/``AssessmentConcurrencySlotORM``: every state-advancing write
is a single conditional ``UPDATE ... WHERE id = ? AND version = ? AND
status = ?``, so two concurrent callers can never both advance the same
occurrence - only one ``UPDATE`` matches, the other affects zero rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

# Sentinel occurrence key for a schedule's first-ever firing, where
# ``ScanSchedule.next_run`` is still ``None`` (see ``ScanSchedule.is_due()``).
# Also covers ONE_TIME schedules, whose ``next_run`` never advances past
# ``None`` (``InProcessScheduler.calculate_next_run()`` always returns
# ``None`` for ``ScheduleType.ONE_TIME``) - reusing this single, stable key
# for every such firing is what makes a one-time schedule's perpetual
# "still due" state safe: after the first successful run, every later poll
# cycle finds the SAME occurrence already ``SUBMITTED`` and does nothing
# further, rather than resubmitting forever.
INITIAL_OCCURRENCE_KEY = "__initial__"


class OccurrenceStatus(StrEnum):
    CLAIMED = "CLAIMED"
    CREATING = "CREATING"
    ASSESSMENT_CREATED = "ASSESSMENT_CREATED"
    SUBMITTING = "SUBMITTING"
    SUBMITTED = "SUBMITTED"


@dataclass(frozen=True, slots=True)
class ScheduleOccurrence:
    """A durable, database-unique record of one schedule firing."""

    id: str
    schedule_id: str
    occurrence_key: str
    status: OccurrenceStatus
    assessment_id: str | None
    version: int
    claimed_at: str
    updated_at: str
