"""SQLAlchemy-backed DeadLetterRepositoryPort."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kingsec.application.distributed.ports import DeadLetterRepositoryPort
from kingsec.domain.job import DeadLetterEntry
from kingsec.infrastructure.persistence.mappers import dead_letter_to_domain, dead_letter_to_orm
from kingsec.infrastructure.persistence.models import DeadLetterEntryModel


class SQLAlchemyDeadLetterRepository(DeadLetterRepositoryPort):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def push(self, entry: DeadLetterEntry) -> DeadLetterEntry:
        orm = dead_letter_to_orm(entry)
        with self._session_factory() as session:
            session.add(orm)
            session.commit()
            return entry

    def get(self, entry_id: str) -> DeadLetterEntry | None:
        stmt = select(DeadLetterEntryModel).where(DeadLetterEntryModel.entry_id == entry_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            return dead_letter_to_domain(orm) if orm else None

    def find_all(self) -> list[DeadLetterEntry]:
        stmt = select(DeadLetterEntryModel).order_by(DeadLetterEntryModel.created_at.desc())
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return [dead_letter_to_domain(r) for r in rows]

    def delete(self, entry_id: str) -> None:
        stmt = select(DeadLetterEntryModel).where(DeadLetterEntryModel.entry_id == entry_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            if orm:
                session.delete(orm)
                session.commit()

    def count(self) -> int:
        with self._session_factory() as session:
            return session.execute(func.count(DeadLetterEntryModel.entry_id)).scalar() or 0
