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

from kingsec.domain.enums import AssessmentStatus


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


# ---------------------------------------------------------------------------
# KSEC-103-01: operator inspection - VISIBILITY FIRST, RECOVERY LATER.
#
# This section adds a derived, read-only classification of an execution
# record given its own status and the durable status of the Assessment it
# belongs to. It classifies; it never mutates. No code path in this module
# (or anywhere else added this phase) writes to the ledger - see
# assessment_execution_repository.py's ``list_with_context`` for the
# read-only query this classification is applied to.
# ---------------------------------------------------------------------------


class ExecutionClassification(StrEnum):
    """A derived, display-only judgement - never a stored execution state
    (Phase 103 explicitly prefers a derived classification over expanding
    the Phase 102 state machine with new persistent statuses like STALE/
    ABANDONED/UNKNOWN/DEAD/RECOVERABLE)."""

    TERMINAL = "TERMINAL"
    RECONCILABLE = "RECONCILABLE"
    UNRESOLVED = "UNRESOLVED"
    # Durable facts that contradict each other (e.g. execution SUCCEEDED
    # but the assessment is still RUNNING) - Phase 103 Test I: "do NOT
    # silently reinterpret contradictory durable facts." Reported
    # conservatively, never guessed at, never mutated.
    INCONSISTENT = "INCONSISTENT"


# Which Assessment statuses each terminal execution status "expects" to see
# - used only to detect INCONSISTENT, never to change behaviour otherwise.
_EXPECTED_ASSESSMENT_STATUS_FOR_SUCCEEDED = AssessmentStatus.COMPLETED
_EXPECTED_ASSESSMENT_STATUS_FOR_FAILED = AssessmentStatus.FAILED
# Assessment statuses that constitute durable terminal evidence (Phase 101
# Section 12 / Phase 102 Step 19's own safe-reconciliation boundary) -
# CANCELLED is deliberately excluded: Phase 102's reconcile_terminal_from_
# evidence() only ever writes SUCCEEDED or FAILED, and nothing in Phase 98-
# 102 established CANCELLED-while-RUNNING as an evidenced, safe-to-
# reconcile case - treating it as reconcilable here would be inventing a
# safety proof this phase was not asked to establish.
_ASSESSMENT_TERMINAL_STATUSES_FOR_RECONCILIATION = frozenset({AssessmentStatus.COMPLETED, AssessmentStatus.FAILED})


def classify_execution(
    execution_status: AssessmentExecutionStatus, assessment_status: AssessmentStatus
) -> ExecutionClassification:
    """Pure, read-only classification - no I/O, no mutation.

    Mirrors the exact Phase 102 semantics (Step 19 / Phase 101 Section 12):
    a RUNNING execution whose Assessment already carries durable terminal
    evidence (COMPLETED or FAILED) is RECONCILABLE; a RUNNING execution
    whose Assessment has not yet reached that evidence is UNRESOLVED,
    exactly like REQUESTED/CLAIMED (Phase 102 never distinguishes those
    three for automatic-recovery purposes - Absolute Rules 6/7/8 forbid
    treating any of them differently without a liveness mechanism this
    phase does not add).
    """
    if execution_status in TERMINAL_EXECUTION_STATUSES:
        expected = (
            _EXPECTED_ASSESSMENT_STATUS_FOR_SUCCEEDED
            if execution_status == AssessmentExecutionStatus.SUCCEEDED
            else _EXPECTED_ASSESSMENT_STATUS_FOR_FAILED
        )
        return ExecutionClassification.TERMINAL if assessment_status == expected else ExecutionClassification.INCONSISTENT

    if execution_status == AssessmentExecutionStatus.RUNNING:
        return (
            ExecutionClassification.RECONCILABLE
            if assessment_status in _ASSESSMENT_TERMINAL_STATUSES_FOR_RECONCILIATION
            else ExecutionClassification.UNRESOLVED
        )

    # REQUESTED / CLAIMED: durable terminal Assessment evidence this early
    # is itself contradictory (the ordering in submit_assessment.py always
    # commits RUNNING before the scanner is ever invoked, so an Assessment
    # cannot legitimately reach COMPLETED/FAILED while the execution record
    # is still REQUESTED/CLAIMED) - reported as INCONSISTENT rather than
    # silently treated as ordinary unresolved.
    if assessment_status in _ASSESSMENT_TERMINAL_STATUSES_FOR_RECONCILIATION:
        return ExecutionClassification.INCONSISTENT
    return ExecutionClassification.UNRESOLVED


@dataclass(frozen=True, slots=True)
class ExecutionInspectionRow:
    """A read-only, joined projection for operator inspection - raw durable
    facts only, no computed classification (the caller applies
    ``classify_execution`` itself; this dataclass never invents a security
    or correctness judgement of its own).

    ``schedule_*``/``occurrence_key``/``schedule_owner_user_id`` are
    ``None`` for a manually-created assessment (Phase 103 Test J) - joined
    in via ``Assessment.schedule_occurrence_id``, itself nullable, exactly
    as established in Phase 98.
    """

    execution_id: str
    assessment_id: str
    execution_status: AssessmentExecutionStatus
    execution_version: int
    execution_created_at: str
    execution_updated_at: str
    assessment_status: AssessmentStatus
    schedule_occurrence_id: str | None
    occurrence_key: str | None
    schedule_id: str | None
    schedule_owner_user_id: str | None
