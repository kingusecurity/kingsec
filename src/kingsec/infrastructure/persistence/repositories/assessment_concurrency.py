"""SQLAlchemy-backed atomic assessment concurrency-slot reservation.

KSEC-87-02: see application/ports/outbound/assessment_concurrency.py for
why this exists and why a naive count-then-write check is unsafe.
"""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy import CursorResult, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.assessment_concurrency import AssessmentConcurrencyPort

_SLOT_ROW_ID = 1


class SqlAlchemyAssessmentConcurrencyRepository(AssessmentConcurrencyPort):
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def try_reserve_slot(self, max_concurrent: int) -> bool:
        """Atomically claim a slot via a single conditional UPDATE.

        The WHERE clause (``active_count < max_concurrent``) and the
        write (``active_count + 1``) are evaluated by the database as one
        statement - there is no separate "read the count, then decide"
        step in this code for a concurrent caller to race. If two callers
        reach capacity simultaneously, the database's own write
        serialization ensures at most one UPDATE actually matches the
        row; the other affects zero rows and this returns False.

        The creating Alembic migration seeds the single counter row, but
        a database created via ``create_schema()`` (test fixtures and the
        documented "quick-start" fallback in database.py - never the
        production ``alembic upgrade head`` path) only creates the empty
        table, with no row to conditionally UPDATE against - every
        reservation would then find zero matching rows and permanently
        reject every assessment. The idempotent ``INSERT ... ON CONFLICT
        DO NOTHING`` below self-heals that case inside the SAME
        transaction as the reservation attempt: it is a no-op once the
        row already exists (the normal, migrated case), and concurrent
        callers racing it are safe too, since SQLite allows only one
        insert to actually land and the rest become no-ops, after which
        every caller proceeds to the same atomic conditional UPDATE.
        """
        from kingsec.infrastructure.persistence.models import AssessmentConcurrencySlotORM

        with self._session_factory.begin() as session:
            session.execute(
                sqlite_insert(AssessmentConcurrencySlotORM)
                .values(id=_SLOT_ROW_ID, active_count=0)
                .on_conflict_do_nothing(index_elements=["id"])
            )
            result = cast(
                "CursorResult[Any]",
                session.execute(
                    update(AssessmentConcurrencySlotORM)
                    .where(
                        AssessmentConcurrencySlotORM.id == _SLOT_ROW_ID,
                        AssessmentConcurrencySlotORM.active_count < max_concurrent,
                    )
                    .values(active_count=AssessmentConcurrencySlotORM.active_count + 1)
                ),
            )
            return result.rowcount == 1

    def release_slot(self) -> None:
        """Atomically release a slot, floored at zero.

        The ``active_count > 0`` guard means a stray/duplicate release
        call (a bug, not the expected one-release-per-successful-reserve
        contract) can never drive the counter negative and silently
        corrupt capacity for every future caller - it just becomes a
        harmless no-op once the count has already reached zero.
        """
        from kingsec.infrastructure.persistence.models import AssessmentConcurrencySlotORM

        with self._session_factory.begin() as session:
            session.execute(
                update(AssessmentConcurrencySlotORM)
                .where(
                    AssessmentConcurrencySlotORM.id == _SLOT_ROW_ID,
                    AssessmentConcurrencySlotORM.active_count > 0,
                )
                .values(active_count=AssessmentConcurrencySlotORM.active_count - 1)
            )
