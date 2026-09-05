"""Use case: explicit, ADMIN-only, human-triggered reconciliation of a
durable assessment execution record (KSEC-105-01).

Phase 104 proved exactly one evidence class is safe to reconcile from
current durable state, and precisely why:

    execution.status = RUNNING, assessment.status = COMPLETED
        -> execution.status = SUCCEEDED

    execution.status = RUNNING, assessment.status = FAILED
        -> execution.status = FAILED

No other combination is reconciled here. This is a LEDGER REPAIR
operation, never an execution operation: it never invokes a scanner,
never creates or submits an Assessment, never touches the scheduler, and
never accepts a caller-supplied outcome - the outcome is derived
exclusively, server-side, from a fresh read of the Assessment's own
durable status at the moment of reconciliation (Phase 105 Steps 5-6).

Reuses Phase 102's ``reconcile_terminal_from_evidence()`` verbatim - no
new state-transition logic is introduced (Phase 105 Step 11). The only
new logic here is the evidence GATE (delegated to Phase 103's own
``classify_execution()``, not reimplemented) and the fresh-read-then-
re-read-on-race sequencing this module owns.
"""

from __future__ import annotations

import logging

from kingsec.application.assessment_execution_ledger import (
    AssessmentExecutionStatus,
    ExecutionClassification,
    ExecutionInspectionRow,
    classify_execution,
)
from kingsec.application.errors import AssessmentExecutionNotReconcilableError
from kingsec.application.ports.outbound.assessment_execution_repository import AssessmentExecutionRepositoryPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.use_cases.execution_inspection_dto import (
    ReconcileAssessmentExecutionRequest,
    ReconcileAssessmentExecutionResult,
)
from kingsec.application.use_cases.inspect_assessment_executions import to_execution_inspection_view
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.enums import AssessmentStatus

logger = logging.getLogger(__name__)


class ReconcileAssessmentExecution:
    """Attempt a narrowly-scoped, evidence-gated terminal reconciliation.

    Constructor-injected with only the execution ledger port and an
    audit publisher - no ``ScannerPort``, no ``JobRunner``, no
    ``AssessmentRepository`` beyond what the ledger's own joined read
    already provides, no ``CreateAssessment``/``SubmitAssessment``/
    ``SubmitScheduledAssessment`` reference anywhere in this class. This
    is a structural guarantee, not merely a convention: none of those
    ports can be reached from here because none is ever injected.
    """

    def __init__(self, executions: AssessmentExecutionRepositoryPort, audit: AuditPublisher | None = None) -> None:
        self._executions = executions
        self._audit = audit

    def execute(self, request: ReconcileAssessmentExecutionRequest) -> ReconcileAssessmentExecutionResult | None:
        # Fresh, authoritative read - never trusts a prior list/get call
        # (Phase 105 Step 6). This single joined query is the entire
        # evidence source; nothing from the request body informs the
        # outcome, because ReconcileAssessmentExecutionRequest carries no
        # such field at all.
        row = self._executions.get_by_id_with_context(request.execution_id)
        if row is None:
            return None

        classification = classify_execution(row.execution_status, row.assessment_status)

        if classification == ExecutionClassification.TERMINAL:
            # Idempotent no-op: already resolved, and the existing terminal
            # status already matches what fresh evidence would produce
            # (classify_execution() only reports TERMINAL when the
            # execution's terminal status agrees with the Assessment's -
            # a mismatched pair is INCONSISTENT, handled below, never here).
            self._publish_audit(
                request,
                row,
                previous_status=row.execution_status,
                resulting_status=row.execution_status,
                mutated=False,
                success=True,
                reason="already terminal with matching durable evidence - no mutation needed",
            )
            return ReconcileAssessmentExecutionResult(
                view=to_execution_inspection_view(row), previous_execution_status=row.execution_status, mutated=False
            )

        if classification != ExecutionClassification.RECONCILABLE:
            # REQUESTED, CLAIMED, RUNNING+non-terminal/missing Assessment
            # evidence, or an INCONSISTENT combination - fail closed. No
            # write of any kind is attempted.
            self._publish_audit(
                request,
                row,
                previous_status=row.execution_status,
                resulting_status=row.execution_status,
                mutated=False,
                success=False,
                reason=f"not reconcilable under the permitted evidence rules (classification={classification.value})",
            )
            raise AssessmentExecutionNotReconcilableError(
                f"execution {row.execution_id} is not currently reconcilable "
                f"(execution_status={row.execution_status.value}, assessment_status={row.assessment_status.value})"
            )

        # RECONCILABLE: execution RUNNING, Assessment COMPLETED or FAILED.
        # The outcome is derived EXCLUSIVELY from the server-read Assessment
        # status just obtained above - never from the request.
        outcome = (
            AssessmentExecutionStatus.SUCCEEDED
            if row.assessment_status == AssessmentStatus.COMPLETED
            else AssessmentExecutionStatus.FAILED
        )

        won = self._executions.reconcile_terminal_from_evidence(row.execution_id, row.execution_version, outcome)
        if won:
            fresh = self._executions.get_by_id_with_context(row.execution_id) or row
            self._publish_audit(
                request,
                fresh,
                previous_status=AssessmentExecutionStatus.RUNNING,
                resulting_status=fresh.execution_status,
                mutated=True,
                success=True,
                reason="evidence-backed terminal reconciliation",
            )
            return ReconcileAssessmentExecutionResult(
                view=to_execution_inspection_view(fresh),
                previous_execution_status=AssessmentExecutionStatus.RUNNING,
                mutated=True,
            )

        # Lost the race - a concurrent worker or another admin's
        # reconciliation already transitioned this record. Re-read once and
        # report the actual, current, authoritative state - never assume,
        # never retry the write (Phase 105 Step 10).
        return self._resolve_after_lost_race(request, row)

    def _resolve_after_lost_race(
        self, request: ReconcileAssessmentExecutionRequest, stale_row: ExecutionInspectionRow
    ) -> ReconcileAssessmentExecutionResult:
        fresh = self._executions.get_by_id_with_context(stale_row.execution_id)
        if fresh is None:  # pragma: no cover - execution rows are never deleted; defensive only
            self._publish_audit(
                request,
                stale_row,
                previous_status=stale_row.execution_status,
                resulting_status=stale_row.execution_status,
                mutated=False,
                success=False,
                reason="lost a concurrent transition race and the execution could not be re-read",
            )
            raise AssessmentExecutionNotReconcilableError(
                f"execution {stale_row.execution_id} could not be re-read after a concurrent transition"
            )

        fresh_classification = classify_execution(fresh.execution_status, fresh.assessment_status)
        if fresh_classification == ExecutionClassification.TERMINAL:
            # A concurrent worker (its own try_mark_succeeded()/
            # try_mark_failed()) or another admin's reconciliation already
            # reached the identical, evidence-correct terminal state.
            self._publish_audit(
                request,
                fresh,
                previous_status=stale_row.execution_status,
                resulting_status=fresh.execution_status,
                mutated=False,
                success=True,
                reason="already reconciled by a concurrent process with matching evidence",
            )
            return ReconcileAssessmentExecutionResult(
                view=to_execution_inspection_view(fresh),
                previous_execution_status=stale_row.execution_status,
                mutated=False,
            )

        # Any other post-race state is not safe to declare success about.
        self._publish_audit(
            request,
            fresh,
            previous_status=stale_row.execution_status,
            resulting_status=fresh.execution_status,
            mutated=False,
            success=False,
            reason=(
                "lost a concurrent transition race and the resulting state is not reconcilable "
                f"(classification={fresh_classification.value})"
            ),
        )
        raise AssessmentExecutionNotReconcilableError(
            f"execution {stale_row.execution_id} could not be safely reconciled (concurrent state change)"
        )

    def _publish_audit(
        self,
        request: ReconcileAssessmentExecutionRequest,
        row: ExecutionInspectionRow,
        *,
        previous_status: AssessmentExecutionStatus,
        resulting_status: AssessmentExecutionStatus,
        mutated: bool,
        success: bool,
        reason: str,
    ) -> None:
        """Best-effort audit, but never a false claim (KSEC-105-01 Step 20)
        - ``resulting_status``/``mutated``/``success`` are always taken
        from the actual, just-observed outcome, never assumed."""
        if self._audit is None:
            return
        try:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.EXECUTION_RECONCILED,
                    resource_type="assessment_execution",
                    resource_id=row.execution_id,
                    success=success,
                    reason=reason,
                    user_id=request.requesting_user,
                    username=request.requesting_username,
                    metadata={
                        "execution_id": row.execution_id,
                        "assessment_id": row.assessment_id,
                        "previous_execution_status": previous_status.value,
                        "resulting_execution_status": resulting_status.value,
                        "evidence_assessment_status": row.assessment_status.value,
                        "mutated": mutated,
                    },
                )
            )
        except Exception as exc:
            logger.warning("audit publish failed (best-effort): %s", exc)
