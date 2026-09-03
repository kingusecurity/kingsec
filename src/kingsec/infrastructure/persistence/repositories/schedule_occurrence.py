"""SQLAlchemy-backed atomic schedule-occurrence claiming (KSEC-98-01).

See application/schedule_occurrence.py for the state machine and
application/ports/outbound/schedule_occurrence_repository.py for why every
transition here is a single conditional UPDATE/INSERT, never a
read-then-decide-then-write sequence. Every WHERE clause matches both
``version`` AND the exact prior ``status`` - matching only the version
would allow an ABA race where a second caller, reading a fresh version
after the first caller's own transition but before it finishes its work,
could pass the same gate again (see schedule_occurrence.py's module
docstring for the concrete race this was found to close).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.schedule_occurrence_repository import ScheduleOccurrenceRepositoryPort
from kingsec.application.schedule_occurrence import OccurrenceStatus, ScheduleOccurrence
from kingsec.infrastructure.persistence.models import ScheduleOccurrenceORM


def _to_domain(orm: ScheduleOccurrenceORM) -> ScheduleOccurrence:
    return ScheduleOccurrence(
        id=orm.id,
        schedule_id=orm.schedule_id,
        occurrence_key=orm.occurrence_key,
        status=OccurrenceStatus(orm.status),
        assessment_id=orm.assessment_id,
        version=orm.version,
        claimed_at=orm.claimed_at,
        updated_at=orm.updated_at,
    )


class SqlAlchemyScheduleOccurrenceRepository(ScheduleOccurrenceRepositoryPort):
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def try_claim(self, schedule_id: str, occurrence_key: str) -> ScheduleOccurrence:
        now = datetime.now(UTC).isoformat()
        new_id = f"occ-{uuid.uuid4().hex}"
        with self._session_factory.begin() as session:
            session.execute(
                sqlite_insert(ScheduleOccurrenceORM)
                .values(
                    id=new_id,
                    schedule_id=schedule_id,
                    occurrence_key=occurrence_key,
                    status=OccurrenceStatus.CLAIMED.value,
                    assessment_id=None,
                    version=1,
                    claimed_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["schedule_id", "occurrence_key"])
            )
            row = session.execute(
                select(ScheduleOccurrenceORM).where(
                    ScheduleOccurrenceORM.schedule_id == schedule_id,
                    ScheduleOccurrenceORM.occurrence_key == occurrence_key,
                )
            ).scalar_one()
            return _to_domain(row)

    def _conditional_transition(
        self,
        occurrence_id: str,
        expected_version: int,
        expected_status: OccurrenceStatus,
        new_status: OccurrenceStatus,
        *,
        assessment_id: str | None = None,
    ) -> bool:
        values: dict[str, Any] = {
            "status": new_status.value,
            "version": ScheduleOccurrenceORM.version + 1,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        if assessment_id is not None:
            values["assessment_id"] = assessment_id

        with self._session_factory.begin() as session:
            result = cast(
                "CursorResult[Any]",
                session.execute(
                    update(ScheduleOccurrenceORM)
                    .where(
                        ScheduleOccurrenceORM.id == occurrence_id,
                        ScheduleOccurrenceORM.version == expected_version,
                        ScheduleOccurrenceORM.status == expected_status.value,
                    )
                    .values(**values)
                ),
            )
            return result.rowcount == 1

    def try_begin_creation(self, occurrence_id: str, expected_version: int) -> int | None:
        ok = self._conditional_transition(
            occurrence_id, expected_version, OccurrenceStatus.CLAIMED, OccurrenceStatus.CREATING
        )
        return expected_version + 1 if ok else None

    def mark_assessment_created(self, occurrence_id: str, expected_version: int, assessment_id: str) -> bool:
        return self._conditional_transition(
            occurrence_id,
            expected_version,
            OccurrenceStatus.CREATING,
            OccurrenceStatus.ASSESSMENT_CREATED,
            assessment_id=assessment_id,
        )

    def revert_to_claimed(self, occurrence_id: str, expected_version: int) -> bool:
        return self._conditional_transition(
            occurrence_id, expected_version, OccurrenceStatus.CREATING, OccurrenceStatus.CLAIMED
        )

    def try_begin_submission(self, occurrence_id: str, expected_version: int) -> int | None:
        ok = self._conditional_transition(
            occurrence_id, expected_version, OccurrenceStatus.ASSESSMENT_CREATED, OccurrenceStatus.SUBMITTING
        )
        return expected_version + 1 if ok else None

    def mark_submitted(self, occurrence_id: str, expected_version: int) -> bool:
        return self._conditional_transition(
            occurrence_id, expected_version, OccurrenceStatus.SUBMITTING, OccurrenceStatus.SUBMITTED
        )

    def revert_to_assessment_created(self, occurrence_id: str, expected_version: int) -> bool:
        return self._conditional_transition(
            occurrence_id, expected_version, OccurrenceStatus.SUBMITTING, OccurrenceStatus.ASSESSMENT_CREATED
        )
