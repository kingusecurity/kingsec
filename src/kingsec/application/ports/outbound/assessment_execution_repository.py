"""Port for durable assessment-execution persistence (KSEC-102-01) — no
infrastructure imports.

See ``application/assessment_execution_ledger.py`` for the state machine
this port enforces atomically, and its module docstring for what this
ledger does and does not prove.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.application.assessment_execution_ledger import AssessmentExecution, AssessmentExecutionStatus


class AssessmentExecutionRepositoryPort(ABC):
    @abstractmethod
    def create_requested(self, assessment_id: str) -> AssessmentExecution:
        """Atomically create the REQUESTED execution row if one doesn't
        already exist for this assessment.

        Implemented as ``INSERT ... ON CONFLICT(assessment_id) DO NOTHING``
        followed by a read of whichever row now exists, inside one
        transaction - so this always returns the current, authoritative
        execution record, whether this call created it (fresh, REQUESTED,
        version 1) or a prior call already did (any status). The database
        UNIQUE constraint on ``assessment_id`` is the actual concurrency
        arbiter (KSEC-102-01, Step 8) - never an application-level check.
        """
        ...

    @abstractmethod
    def get_by_assessment_id(self, assessment_id: str) -> AssessmentExecution | None:
        """Return the execution record for the given assessment, or
        ``None`` if none exists yet."""
        ...

    @abstractmethod
    def try_claim(self, execution_id: str, expected_version: int) -> int | None:
        """Atomically reserve the exclusive right to invoke the scanner:
        ``REQUESTED -> CLAIMED``.

        A single conditional ``UPDATE ... WHERE id = ? AND version = ? AND
        status = 'REQUESTED'``. Returns the new version if this call won,
        or ``None`` if it lost - in which case the caller MUST NOT invoke
        the scanner (KSEC-102-01, Step 15).
        """
        ...

    @abstractmethod
    def try_mark_running(self, execution_id: str, expected_version: int) -> int | None:
        """Atomically record ``CLAIMED -> RUNNING``, durably committed
        BEFORE the scanner is invoked (KSEC-102-01, Step 16). Same pattern
        as ``try_claim`` - ``None`` means the caller lost and must not
        invoke the scanner.
        """
        ...

    @abstractmethod
    def try_mark_succeeded(self, execution_id: str, expected_version: int) -> bool:
        """Atomically record ``RUNNING -> SUCCEEDED``. Must only be called
        after the assessment itself has durably reached COMPLETED
        (KSEC-102-01, Step 17) - this method trusts the caller to have
        already established that fact; it does not re-check Assessment
        state itself.
        """
        ...

    @abstractmethod
    def try_mark_failed(self, execution_id: str, expected_version: int) -> bool:
        """Atomically record ``RUNNING -> FAILED``. Must only be called
        after the assessment itself has durably reached FAILED
        (KSEC-102-01, Step 18) - same trust boundary as
        ``try_mark_succeeded``.
        """
        ...

    @abstractmethod
    def reconcile_terminal_from_evidence(
        self, execution_id: str, expected_version: int, outcome: AssessmentExecutionStatus
    ) -> bool:
        """Safely reconcile a stale ``RUNNING`` execution record when the
        Assessment itself already carries durable terminal evidence
        (KSEC-102-01, Step 19 / Phase 101 Section 12, Cases D and E).

        ``outcome`` must be ``SUCCEEDED`` or ``FAILED`` - raises
        ``ValueError`` otherwise. The caller (never this method) is
        responsible for having already confirmed, from durable Assessment
        state, which outcome applies; this is never invoked on a timeout or
        any other non-evidence-based signal (KSEC-102-01 Absolute Rule 6).
        Gated on the same ``WHERE id = ? AND version = ? AND status =
        'RUNNING'`` conditional UPDATE as every other transition here, so
        two concurrent reconciliation attempts (or a genuine worker
        completing normally at the same instant) can never both succeed.
        """
        ...
