"""SQLAlchemy-backed durable assessment-execution ledger (KSEC-102-01).

See application/assessment_execution_ledger.py for the state machine and
application/ports/outbound/assessment_execution_repository.py for why
every transition here is a single conditional UPDATE/INSERT, never a
read-then-decide-then-write sequence - the same discipline established by
SqlAlchemyScheduleOccurrenceRepository (KSEC-98-01), reused verbatim here.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.assessment_execution_ledger import (
    AssessmentExecution,
    AssessmentExecutionStatus,
    ExecutionInspectionRow,
)
from kingsec.application.ports.outbound.assessment_execution_repository import AssessmentExecutionRepositoryPort
from kingsec.domain.enums import AssessmentStatus
from kingsec.infrastructure.persistence.models import (
    AssessmentExecutionORM,
    AssessmentORM,
    ScheduleOccurrenceORM,
    ScheduleORM,
)


def _to_domain(orm: AssessmentExecutionORM) -> AssessmentExecution:
    return AssessmentExecution(
        id=orm.id,
        assessment_id=orm.assessment_id,
        status=AssessmentExecutionStatus(orm.status),
        version=orm.version,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def _inspection_select() -> Any:
    """The one, shared, purpose-built read query (KSEC-103-01) joining
    assessment_executions -> assessments -> schedule_occurrences ->
    schedules.

    No foreign keys back this join (Phase 102 deliberately left
    assessment_executions.assessment_id and schedule_occurrences.
    assessment_id unconstrained - see both tables' own docstrings) - the
    ON clauses are explicit equality conditions over plain, indexed-by-
    primary-key columns, exactly like Phase 100's own
    find_assessments_by_schedule_occurrence_id(). Both joins to
    schedule_occurrences/schedules are LEFT OUTER, since a manually-created
    assessment has no schedule at all (Phase 103 Test J).
    """
    return (
        select(
            AssessmentExecutionORM.id,
            AssessmentExecutionORM.assessment_id,
            AssessmentExecutionORM.status,
            AssessmentExecutionORM.version,
            AssessmentExecutionORM.created_at,
            AssessmentExecutionORM.updated_at,
            AssessmentORM.status,
            ScheduleOccurrenceORM.id,
            ScheduleOccurrenceORM.occurrence_key,
            ScheduleOccurrenceORM.schedule_id,
            ScheduleORM.owner_user_id,
        )
        .join(AssessmentORM, AssessmentExecutionORM.assessment_id == AssessmentORM.id)
        .outerjoin(ScheduleOccurrenceORM, AssessmentORM.schedule_occurrence_id == ScheduleOccurrenceORM.id)
        .outerjoin(ScheduleORM, ScheduleOccurrenceORM.schedule_id == ScheduleORM.id)
    )


def _row_to_inspection(row: Any) -> ExecutionInspectionRow:
    (
        execution_id,
        assessment_id,
        execution_status,
        execution_version,
        execution_created_at,
        execution_updated_at,
        assessment_status,
        schedule_occurrence_id,
        occurrence_key,
        schedule_id,
        schedule_owner_user_id,
    ) = row
    return ExecutionInspectionRow(
        execution_id=execution_id,
        assessment_id=assessment_id,
        execution_status=AssessmentExecutionStatus(execution_status),
        execution_version=execution_version,
        execution_created_at=execution_created_at,
        execution_updated_at=execution_updated_at,
        # KSEC-106-01: AssessmentORM.status stores the enum MEMBER NAME
        # (assessment.status.name, e.g. "RUNNING"), not its value
        # ("running") - see mappers.py's assessment_to_domain(), which
        # already parses it the same way (AssessmentStatus[orm.status]).
        # The previous value-based AssessmentStatus(assessment_status)
        # lookup here raised ValueError for every real, production-created
        # Assessment; every existing test that passed was seeding a
        # hand-typed lowercase ORM value bypassing the real domain/mapper
        # path entirely (Phase 106 finding).
        assessment_status=AssessmentStatus[assessment_status],
        schedule_occurrence_id=schedule_occurrence_id,
        occurrence_key=occurrence_key,
        schedule_id=schedule_id,
        schedule_owner_user_id=schedule_owner_user_id,
    )


class SqlAlchemyAssessmentExecutionRepository(AssessmentExecutionRepositoryPort):
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_requested(self, assessment_id: str) -> AssessmentExecution:
        now = datetime.now(UTC).isoformat()
        new_id = f"exec-{uuid.uuid4().hex}"
        with self._session_factory.begin() as session:
            session.execute(
                sqlite_insert(AssessmentExecutionORM)
                .values(
                    id=new_id,
                    assessment_id=assessment_id,
                    status=AssessmentExecutionStatus.REQUESTED.value,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["assessment_id"])
            )
            row = session.execute(
                select(AssessmentExecutionORM).where(AssessmentExecutionORM.assessment_id == assessment_id)
            ).scalar_one()
            return _to_domain(row)

    def get_by_assessment_id(self, assessment_id: str) -> AssessmentExecution | None:
        with self._session_factory() as session:
            row = session.execute(
                select(AssessmentExecutionORM).where(AssessmentExecutionORM.assessment_id == assessment_id)
            ).scalar_one_or_none()
            return _to_domain(row) if row is not None else None

    def _conditional_transition(
        self,
        execution_id: str,
        expected_version: int,
        expected_status: AssessmentExecutionStatus,
        new_status: AssessmentExecutionStatus,
    ) -> bool:
        with self._session_factory.begin() as session:
            result = cast(
                "CursorResult[Any]",
                session.execute(
                    update(AssessmentExecutionORM)
                    .where(
                        AssessmentExecutionORM.id == execution_id,
                        AssessmentExecutionORM.version == expected_version,
                        AssessmentExecutionORM.status == expected_status.value,
                    )
                    .values(
                        status=new_status.value,
                        version=AssessmentExecutionORM.version + 1,
                        updated_at=datetime.now(UTC).isoformat(),
                    )
                ),
            )
            return result.rowcount == 1

    def try_claim(self, execution_id: str, expected_version: int) -> int | None:
        ok = self._conditional_transition(
            execution_id, expected_version, AssessmentExecutionStatus.REQUESTED, AssessmentExecutionStatus.CLAIMED
        )
        return expected_version + 1 if ok else None

    def try_mark_running(self, execution_id: str, expected_version: int) -> int | None:
        ok = self._conditional_transition(
            execution_id, expected_version, AssessmentExecutionStatus.CLAIMED, AssessmentExecutionStatus.RUNNING
        )
        return expected_version + 1 if ok else None

    def try_mark_succeeded(self, execution_id: str, expected_version: int) -> bool:
        return self._conditional_transition(
            execution_id, expected_version, AssessmentExecutionStatus.RUNNING, AssessmentExecutionStatus.SUCCEEDED
        )

    def try_mark_failed(self, execution_id: str, expected_version: int) -> bool:
        return self._conditional_transition(
            execution_id, expected_version, AssessmentExecutionStatus.RUNNING, AssessmentExecutionStatus.FAILED
        )

    def reconcile_terminal_from_evidence(
        self, execution_id: str, expected_version: int, outcome: AssessmentExecutionStatus
    ) -> bool:
        if outcome not in (AssessmentExecutionStatus.SUCCEEDED, AssessmentExecutionStatus.FAILED):
            raise ValueError(f"reconciliation outcome must be SUCCEEDED or FAILED, got {outcome!r}")
        return self._conditional_transition(
            execution_id, expected_version, AssessmentExecutionStatus.RUNNING, outcome
        )

    def get_by_id_with_context(self, execution_id: str) -> ExecutionInspectionRow | None:
        with self._session_factory() as session:
            row = session.execute(_inspection_select().where(AssessmentExecutionORM.id == execution_id)).first()
            return _row_to_inspection(row) if row is not None else None

    def list_with_context(
        self,
        *,
        statuses: Sequence[AssessmentExecutionStatus] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ExecutionInspectionRow], int]:
        base_query = _inspection_select()
        count_query = select(func.count()).select_from(AssessmentExecutionORM).join(
            AssessmentORM, AssessmentExecutionORM.assessment_id == AssessmentORM.id
        )
        if statuses:
            # Allowlisted IN-filter: `statuses` is always a sequence of the
            # real AssessmentExecutionStatus enum (never a client-supplied
            # raw string - the HTTP layer validates via the enum type
            # before this is ever called), so this is parameterized by
            # SQLAlchemy exactly like every other value here - never string
            # concatenation.
            status_values = [s.value for s in statuses]
            base_query = base_query.where(AssessmentExecutionORM.status.in_(status_values))
            count_query = count_query.where(AssessmentExecutionORM.status.in_(status_values))

        with self._session_factory() as session:
            total = session.execute(count_query).scalar_one()
            rows = session.execute(
                base_query.order_by(AssessmentExecutionORM.updated_at.asc()).limit(limit).offset(offset)
            ).all()
            return [_row_to_inspection(row) for row in rows], total
