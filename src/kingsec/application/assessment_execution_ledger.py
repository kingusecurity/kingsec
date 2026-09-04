"""AssessmentExecution: the durable record of one assessment's execution
attempt (KSEC-102-01).

Phase 99 proved a real, unclean process termination between
``SubmitAssessment.execute()`` returning and ``ThreadJobRunner``'s
background thread finishing leaves no durable trace of whether the scan
actually started, ran, or finished - only the in-memory
``AssessmentExecutionEngine`` (ephemeral - see its own docstring) and
``ThreadJobRunner``'s own in-memory futures dict knew. Phase 101 designed
the smallest durable ledger that could close that visibility gap without
claiming a stronger property than it can prove; this module is that
ledger's data shape.

State machine - four real states plus one terminal fork (see
``AssessmentExecutionRepositoryPort`` for the exact conditional-UPDATE
transitions this enforces):

    REQUESTED   -- SubmitAssessment.execute() has durably recorded intent
                   to execute, synchronously, before the background job is
                   even submitted to ThreadJobRunner
        --> CLAIMED     (the background worker won the exclusive right to
                          actually invoke the scanner)
    CLAIMED     -- exactly one worker has the right to proceed
        --> RUNNING     (durably committed BEFORE the scanner is invoked -
                          see submit_assessment.py's _execute_scan())
    RUNNING     -- the scanner has actually been invoked
        --> SUCCEEDED   (the assessment durably reached COMPLETED)
        --> FAILED      (the assessment durably reached FAILED)
    SUCCEEDED   -- terminal
    FAILED      -- terminal

Every state-advancing write is a single conditional ``UPDATE ... WHERE id
= ? AND version = ? AND status = ?`` (the same optimistic-lock idiom
already used by ``ScheduleOccurrenceORM``/``ScheduleORM``), so two
concurrent callers can never both advance the same execution record - only
one ``UPDATE`` matches, the other affects zero rows and must not proceed
to invoke the scanner (KSEC-102-01, Step 15).

What this ledger proves and does NOT prove (Phase 101 Section 18,
unchanged by this implementation): it proves there is one durable
execution record per assessment with atomic, database-enforced state
transitions and durable evidence of execution progress/result. It does
NOT prove exactly-once scanner execution, automatic crash recovery, or
external-side-effect idempotency - see the Phase 102 final report for the
full, evidence-labelled breakdown.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AssessmentExecutionStatus(StrEnum):
    REQUESTED = "REQUESTED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


# The two states from which no further transition is ever legal - a
# terminal execution record is durable evidence and must never become
# mutable again (KSEC-102-01, Step 26).
TERMINAL_EXECUTION_STATUSES = frozenset({AssessmentExecutionStatus.SUCCEEDED, AssessmentExecutionStatus.FAILED})


@dataclass(frozen=True, slots=True)
class AssessmentExecution:
    """A durable, database-unique record of one assessment's execution attempt.

    Identity is ``assessment_id`` (database-enforced ``UNIQUE`` - see the
    repository) - the current Assessment domain model has no transition
    back out of a terminal status, so it structurally cannot be
    re-executed, and therefore one assessment can never legitimately have
    more than one execution record (Phase 101 Section 4). ``id`` is a
    separate, opaque surrogate primary key, matching the existing
    ``ScheduleOccurrenceORM`` convention rather than making the natural key
    the primary key itself.
    """

    id: str
    assessment_id: str
    status: AssessmentExecutionStatus
    version: int
    created_at: str
    updated_at: str
