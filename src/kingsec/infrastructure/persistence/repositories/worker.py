"""SQLAlchemy-backed WorkerRepositoryPort."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application.distributed.ports import WorkerRepositoryPort
from kingsec.domain.job import WorkerNode, WorkerStatus
from kingsec.infrastructure.persistence.mappers import worker_to_domain, worker_to_orm
from kingsec.infrastructure.persistence.models import WorkerModel


class SQLAlchemyWorkerRepository(WorkerRepositoryPort):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def register(self, worker: WorkerNode) -> WorkerNode:
        orm = worker_to_orm(worker)
        with self._session_factory() as session:
            session.add(orm)
            session.commit()
            return worker

    def get(self, worker_id: str) -> WorkerNode | None:
        stmt = select(WorkerModel).where(WorkerModel.worker_id == worker_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            return worker_to_domain(orm) if orm else None

    def find_all(self) -> list[WorkerNode]:
        stmt = select(WorkerModel).order_by(WorkerModel.created_at)
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return [worker_to_domain(r) for r in rows]

    def find_online(self) -> list[WorkerNode]:
        stmt = select(WorkerModel).where(WorkerModel.status.in_([WorkerStatus.ONLINE.value, WorkerStatus.BUSY.value]))
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return [worker_to_domain(r) for r in rows]

    def find_idle(self) -> list[WorkerNode]:
        stmt = select(WorkerModel).where(WorkerModel.status == WorkerStatus.ONLINE.value)
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return [worker_to_domain(r) for r in rows]

    def update(self, worker: WorkerNode) -> None:
        orm = worker_to_orm(worker)
        with self._session_factory() as session:
            session.merge(orm)
            session.commit()

    def delete(self, worker_id: str) -> None:
        stmt = select(WorkerModel).where(WorkerModel.worker_id == worker_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            if orm:
                session.delete(orm)
                session.commit()
