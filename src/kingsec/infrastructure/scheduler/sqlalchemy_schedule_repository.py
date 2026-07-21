"""SQLAlchemy-backed schedule repository."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.schedule import (
    RetryPolicy,
    RetryStrategy,
    ScanSchedule,
    ScheduleId,
    ScheduleStatus,
    ScheduleType,
)


class SqlAlchemyScheduleRepository(ScheduleRepositoryPort):
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, schedule: ScanSchedule) -> None:
        with self._session_factory.begin() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.id == str(schedule.id))
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is None:
                orm = ScheduleORM(id=str(schedule.id))
                session.add(orm)
            self._update_orm(orm, schedule)

    def find_by_id(self, schedule_id: str) -> ScanSchedule | None:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.id == schedule_id)
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is None:
                return None
            return self._to_domain(orm)

    def find_by_user_id(self, user_id: str) -> list[ScanSchedule]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.owner_user_id == user_id).order_by(ScheduleORM.created_at)
            return [self._to_domain(orm) for orm in session.execute(stmt).scalars().all()]

    def find_all(self) -> list[ScanSchedule]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).order_by(ScheduleORM.created_at)
            return [self._to_domain(orm) for orm in session.execute(stmt).scalars().all()]

    def find_due(self, now_utc_str: str) -> list[ScanSchedule]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = (
                select(ScheduleORM)
                .where(ScheduleORM.enabled == True)  # noqa: E712
                .where(ScheduleORM.paused == False)  # noqa: E712
                .where(
                    (ScheduleORM.next_run.is_(None)) | (ScheduleORM.next_run <= now_utc_str)
                )
                .order_by(ScheduleORM.created_at)
            )
            return [self._to_domain(orm) for orm in session.execute(stmt).scalars().all()]

    def delete(self, schedule_id: str) -> None:
        with self._session_factory.begin() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.id == schedule_id)
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is not None:
                session.delete(orm)

    @staticmethod
    def _to_domain(orm: object) -> ScanSchedule:
        from typing import Any
        o: Any = orm
        return ScanSchedule(
            id=ScheduleId(value=o.id),
            name=o.name,
            description=o.description,
            owner_user_id=o.owner_user_id,
            target=o.target,
            scanner_ids=tuple(o.scanner_ids or []),
            config=dict(o.config or {}),
            schedule_type=ScheduleType(o.schedule_type),
            cron_expression=o.cron_expression or "",
            timezone=o.timezone or "UTC",
            enabled=o.enabled,
            paused=o.paused,
            created_at=o.created_at,
            updated_at=o.updated_at,
            last_run=o.last_run,
            next_run=o.next_run,
            retry_policy=RetryPolicy(
                strategy=RetryStrategy(o.retry_strategy or "no_retry"),
                max_retries=o.max_retries or 0,
                retry_delay_seconds=o.retry_delay_seconds or 0,
            ),
            current_retry_count=o.current_retry_count or 0,
            status=ScheduleStatus(o.status or "active"),
        )

    @staticmethod
    def _update_orm(orm: object, s: ScanSchedule) -> None:
        from typing import Any
        o: Any = orm
        o.name = s.name
        o.description = s.description
        o.owner_user_id = s.owner_user_id
        o.target = s.target
        o.scanner_ids = list(s.scanner_ids)
        o.config = dict(s.config)
        o.schedule_type = s.schedule_type.value
        o.cron_expression = s.cron_expression
        o.timezone = s.timezone
        o.enabled = s.enabled
        o.paused = s.paused
        o.created_at = s.created_at
        o.updated_at = s.updated_at
        o.last_run = s.last_run
        o.next_run = s.next_run
        o.retry_strategy = s.retry_policy.strategy.value
        o.max_retries = s.retry_policy.max_retries
        o.retry_delay_seconds = s.retry_policy.retry_delay_seconds
        o.current_retry_count = s.current_retry_count
        o.status = s.status.value
