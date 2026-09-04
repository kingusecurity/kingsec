"""SQLAlchemy-backed durable assessment-execution ledger (KSEC-102-01).

See application/assessment_execution_ledger.py for the state machine and
application/ports/outbound/assessment_execution_repository.py for why
every transition here is a single conditional UPDATE/INSERT, never a
read-then-decide-then-write sequence - the same discipline established by
SqlAlchemyScheduleOccurrenceRepository (KSEC-98-01), reused verbatim here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.assessment_execution_ledger import AssessmentExecution, AssessmentExecutionStatus
from kingsec.application.ports.outbound.assessment_execution_repository import AssessmentExecutionRepositoryPort
from kingsec.infrastructure.persistence.models import AssessmentExecutionORM


def _to_domain(orm: AssessmentExecutionORM) -> AssessmentExecution:
    return AssessmentExecution(
        id=orm.id,
        assessment_id=orm.assessment_id,
        status=AssessmentExecutionStatus(orm.status),
        version=orm.version,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
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
