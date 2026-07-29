"""SQLAlchemy-backed JobQueueRepositoryPort."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kingsec.application.distributed.ports import JobQueueRepositoryPort
from kingsec.domain.job import JobQueueEntry, JobState, QueueMetrics
from kingsec.infrastructure.persistence.mappers import job_queue_entry_to_domain, job_queue_entry_to_orm
from kingsec.infrastructure.persistence.models import DeadLetterEntryModel, JobQueueEntryModel


class SQLAlchemyJobQueueRepository(JobQueueRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def enqueue(self, entry: JobQueueEntry) -> JobQueueEntry:
        orm = job_queue_entry_to_orm(entry)
        self._session.add(orm)
        self._session.flush()
        return entry

    def get(self, entry_id: str) -> JobQueueEntry | None:
        stmt = select(JobQueueEntryModel).where(JobQueueEntryModel.entry_id == entry_id)
        orm = self._session.execute(stmt).scalar_one_or_none()
        return job_queue_entry_to_domain(orm) if orm else None

    def find_by_state(self, state: str) -> list[JobQueueEntry]:
        stmt = select(JobQueueEntryModel).where(JobQueueEntryModel.state == state)
        rows = self._session.execute(stmt).scalars().all()
        return [job_queue_entry_to_domain(r) for r in rows]

    def find_all(self) -> list[JobQueueEntry]:
        stmt = select(JobQueueEntryModel).order_by(JobQueueEntryModel.created_at)
        rows = self._session.execute(stmt).scalars().all()
        return [job_queue_entry_to_domain(r) for r in rows]

    def update(self, entry: JobQueueEntry) -> None:
        orm = job_queue_entry_to_orm(entry)
        self._session.merge(orm)
        self._session.flush()

    def delete(self, entry_id: str) -> None:
        stmt = select(JobQueueEntryModel).where(JobQueueEntryModel.entry_id == entry_id)
        orm = self._session.execute(stmt).scalar_one_or_none()
        if orm:
            self._session.delete(orm)
            self._session.flush()

    def get_metrics(self) -> QueueMetrics:
        total = self._session.execute(select(func.count(JobQueueEntryModel.entry_id))).scalar() or 0
        queued = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.QUEUED.value)
        ).scalar() or 0
        assigned = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.ASSIGNED.value)
        ).scalar() or 0
        running = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.RUNNING.value)
        ).scalar() or 0
        completed = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.COMPLETED.value)
        ).scalar() or 0
        failed = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.FAILED.value)
        ).scalar() or 0
        cancelled = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.CANCELLED.value)
        ).scalar() or 0
        retrying = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.RETRYING.value)
        ).scalar() or 0
        expired = self._session.execute(
            select(func.count(JobQueueEntryModel.entry_id)).where(JobQueueEntryModel.state == JobState.EXPIRED.value)
        ).scalar() or 0
        dead_letter = self._session.execute(
            select(func.count(DeadLetterEntryModel.entry_id))
        ).scalar() or 0
        now = datetime.now(UTC).isoformat()
        oldest = self._session.execute(
            select(func.min(JobQueueEntryModel.created_at)).where(
                JobQueueEntryModel.state.in_([JobState.QUEUED.value, JobState.ASSIGNED.value, JobState.RUNNING.value])
            )
        ).scalar()
        avg_wait = 0.0
        oldest_age = 0.0
        if oldest:
            try:
                oldest_dt = datetime.fromisoformat(oldest)
                now_dt = datetime.fromisoformat(now)
                oldest_age = (now_dt - oldest_dt).total_seconds()
            except (ValueError, TypeError):
                pass
        return QueueMetrics(
            total_queued=queued,
            total_assigned=assigned,
            total_running=running,
            total_completed=completed,
            total_failed=failed,
            total_cancelled=cancelled,
            total_retrying=retrying,
            total_expired=expired,
            total_dead_letter=dead_letter,
            average_wait_seconds=avg_wait,
            oldest_job_age_seconds=oldest_age,
        )

    def find_queued(self) -> list[JobQueueEntry]:
        return self.find_by_state(JobState.QUEUED.value)

    def find_assigned(self) -> list[JobQueueEntry]:
        return self.find_by_state(JobState.ASSIGNED.value)

    def find_retrying(self) -> list[JobQueueEntry]:
        return self.find_by_state(JobState.RETRYING.value)

    def find_expired(self) -> list[JobQueueEntry]:
        return self.find_by_state(JobState.EXPIRED.value)
