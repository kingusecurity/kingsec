"""Use cases: safe, read-only operator inspection of the durable assessment
execution ledger (KSEC-103-01).

VISIBILITY FIRST, RECOVERY LATER: these use cases classify executions
(TERMINAL / RECONCILABLE / UNRESOLVED / INCONSISTENT) from durable evidence
already on disk. Neither use case in this module ever writes to the
ledger, the Assessment, or invokes a scanner - they call only
``list_with_context``/``get_by_id_with_context``, which are themselves
read-only queries (see ``assessment_execution_repository.py``).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from kingsec.application.assessment_execution_ledger import (
    AssessmentExecutionStatus,
    ExecutionInspectionRow,
    classify_execution,
)
from kingsec.application.ports.outbound.assessment_execution_repository import AssessmentExecutionRepositoryPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.use_cases.execution_inspection_dto import (
    ExecutionInspectionView,
    GetAssessmentExecutionRequest,
    ListAssessmentExecutionsRequest,
    ListAssessmentExecutionsResponse,
)
from kingsec.domain.audit import AuditAction, AuditEntry

# Phase 102's own non-terminal statuses, reused here (not redefined) so a
# future change to the state machine's shape cannot silently desynchronize
# "what counts as unresolved" between the two modules.

_NON_TERMINAL_STATUSES = (
    AssessmentExecutionStatus.REQUESTED,
    AssessmentExecutionStatus.CLAIMED,
    AssessmentExecutionStatus.RUNNING,
)


def _to_view(row: ExecutionInspectionRow) -> ExecutionInspectionView:
    return ExecutionInspectionView(
        execution_id=row.execution_id,
        assessment_id=row.assessment_id,
        execution_status=row.execution_status,
        execution_version=row.execution_version,
        execution_created_at=row.execution_created_at,
        execution_updated_at=row.execution_updated_at,
        assessment_status=row.assessment_status.value,
        classification=classify_execution(row.execution_status, row.assessment_status),
        schedule_occurrence_id=row.schedule_occurrence_id,
        occurrence_key=row.occurrence_key,
        schedule_id=row.schedule_id,
        schedule_owner_user_id=row.schedule_owner_user_id,
    )


class ListAssessmentExecutions:
    """List durable execution records with derived classification, for
    authorized administrators only (enforced at the web layer - this use
    case does not itself check roles, matching every other use case in
    this codebase, which trusts its caller to have already gated access).
    """

    def __init__(self, executions: AssessmentExecutionRepositoryPort, audit: AuditPublisher | None = None) -> None:
        self._executions = executions
        self._audit = audit

    def execute(self, request: ListAssessmentExecutionsRequest) -> ListAssessmentExecutionsResponse:
        statuses: Sequence[AssessmentExecutionStatus] | None
        if request.status is not None:
            statuses = (request.status,)
        elif request.unresolved_only:
            statuses = _NON_TERMINAL_STATUSES
        else:
            statuses = None

        rows, total = self._executions.list_with_context(
            statuses=statuses, limit=request.limit, offset=request.offset
        )
        views = [_to_view(row) for row in rows]

        self._publish_audit(request, views, total)

        return ListAssessmentExecutionsResponse(items=views, total=total, limit=request.limit, offset=request.offset)

    def _publish_audit(
        self, request: ListAssessmentExecutionsRequest, views: list[ExecutionInspectionView], total: int
    ) -> None:
        """Best-effort audit of the administrative inspection itself
        (KSEC-103-01) - a summary, not one entry per row, to avoid audit-
        log noise from a routine, read-only query."""
        if self._audit is None:
            return
        classifications = [v.classification.value for v in views]
        try:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.EXECUTION_INSPECTED,
                    resource_type="assessment_execution",
                    resource_id="*",
                    success=True,
                    user_id=request.requesting_user,
                    username=request.requesting_username,
                    metadata={
                        "unresolved_only": request.unresolved_only,
                        "status_filter": request.status.value if request.status else None,
                        "returned_count": len(views),
                        "total_matching": total,
                        "classifications": classifications,
                    },
                )
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)


class GetAssessmentExecution:
    """Look up a single execution's full inspection context by execution id."""

    def __init__(self, executions: AssessmentExecutionRepositoryPort, audit: AuditPublisher | None = None) -> None:
        self._executions = executions
        self._audit = audit

    def execute(self, request: GetAssessmentExecutionRequest) -> ExecutionInspectionView | None:
        row = self._executions.get_by_id_with_context(request.execution_id)
        if row is None:
            return None
        view = _to_view(row)
        self._publish_audit(request, view)
        return view

    def _publish_audit(self, request: GetAssessmentExecutionRequest, view: ExecutionInspectionView) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.EXECUTION_INSPECTED,
                    resource_type="assessment_execution",
                    resource_id=view.execution_id,
                    success=True,
                    user_id=request.requesting_user,
                    username=request.requesting_username,
                    metadata={
                        "execution_id": view.execution_id,
                        "assessment_id": view.assessment_id,
                        "execution_status": view.execution_status.value,
                        "classification": view.classification.value,
                    },
                )
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)
