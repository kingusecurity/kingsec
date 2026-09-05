"""DTOs for durable assessment-execution inspection (KSEC-103-01).

Read-only: nothing here ever causes a state transition. See
``inspect_assessment_executions.py`` for the use cases that produce these.
"""

from __future__ import annotations

from dataclasses import dataclass

from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus, ExecutionClassification


@dataclass(frozen=True)
class ExecutionInspectionView:
    """One execution's full, operator-facing inspection record.

    Contains only information appropriate for an authorized administrator
    (KSEC-103-01's own "Minimum Information Model" review) - no scanner
    credentials, secrets, tokens, or raw exception detail are ever sourced
    into this view, because none of the underlying query's columns carry
    any (see ``ExecutionInspectionRow``).
    """

    execution_id: str
    assessment_id: str
    execution_status: AssessmentExecutionStatus
    execution_version: int
    execution_created_at: str
    execution_updated_at: str
    assessment_status: str
    classification: ExecutionClassification
    schedule_occurrence_id: str | None
    occurrence_key: str | None
    schedule_id: str | None
    schedule_owner_user_id: str | None


@dataclass(frozen=True)
class ListAssessmentExecutionsRequest:
    """``unresolved_only`` and ``status`` may be combined (AND) - both are
    safe, allowlisted filters (an enum member and a bool), never raw
    client-supplied strings reaching the query layer.
    """

    unresolved_only: bool = False
    status: AssessmentExecutionStatus | None = None
    limit: int = 50
    offset: int = 0
    requesting_user: str = ""
    requesting_username: str = ""


@dataclass(frozen=True)
class ListAssessmentExecutionsResponse:
    items: list[ExecutionInspectionView]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True)
class GetAssessmentExecutionRequest:
    execution_id: str
    requesting_user: str = ""
    requesting_username: str = ""
