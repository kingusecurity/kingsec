"""SQLAlchemy-backed schedule repository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.errors import ScheduleConflictError
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
        """Insert a new schedule, or update an existing one.

        KSEC-85-02: the update path is optimistic-locked. ``schedule.version``
        must be the version this caller originally read (via find_by_id()/
        find_due()) - every sibling use case (pause/resume/update/enable/
        disable/trigger) and the in-process scheduler carry it forward
        unchanged from their own read. The UPDATE is scoped to
        ``WHERE id = ? AND version = ?`` and sets ``version = version + 1``;
        if another writer already advanced the version, zero rows match and
        ScheduleConflictError is raised - never silently overwriting, never
        silently overwritten, never automatically retried.

        KSEC-88-03: delete() (below) is a tombstone, not a physical
        removal - it sets ``deleted_at`` rather than dropping the row. A
        query for the id below therefore has three outcomes, not two: no
        row at all (genuinely never existed - safe to insert), a row with
        ``deleted_at`` set (existed, was deleted - always a conflict,
        regardless of the version this caller read), or a live row
        (normal optimistic-locked update path). This closes the KSEC-87-03
        residual gap directly: that fix could only infer "probably
        deleted" from `version != 1`, which couldn't tell a stale
        version-1 write (read before the schedule's first-ever update)
        apart from a genuinely new id - the tombstone makes that
        distinction exact instead of inferred, so the version-based check
        this replaced is no longer needed.
        """
        with self._session_factory.begin() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            row = session.execute(
                select(ScheduleORM.deleted_at).where(ScheduleORM.id == str(schedule.id))
            ).one_or_none()
            if row is None:
                orm = ScheduleORM(id=str(schedule.id), version=schedule.version)
                session.add(orm)
                self._update_orm(orm, schedule)
                return
            if row[0] is not None:
                raise ScheduleConflictError(
                    f"schedule '{schedule.id}' was deleted by another request since it was last read"
                )

            result = cast(
                "CursorResult[Any]",
                session.execute(
                    update(ScheduleORM)
                    .where(ScheduleORM.id == str(schedule.id), ScheduleORM.version == schedule.version)
                    .values(**self._field_values(schedule), version=ScheduleORM.version + 1)
                ),
            )
            if result.rowcount == 0:
                raise ScheduleConflictError(
                    f"schedule '{schedule.id}' was modified by another request since it was last read"
                )

    def find_by_id(self, schedule_id: str) -> ScanSchedule | None:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.id == schedule_id, ScheduleORM.deleted_at.is_(None))
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is None:
                return None
            return self._to_domain(orm)

    def find_by_user_id(self, user_id: str) -> list[ScanSchedule]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = (
                select(ScheduleORM)
                .where(ScheduleORM.owner_user_id == user_id, ScheduleORM.deleted_at.is_(None))
                .order_by(ScheduleORM.created_at)
            )
            return [self._to_domain(orm) for orm in session.execute(stmt).scalars().all()]

    def find_all(self) -> list[ScanSchedule]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.deleted_at.is_(None)).order_by(ScheduleORM.created_at)
            return [self._to_domain(orm) for orm in session.execute(stmt).scalars().all()]

    def find_due(self, now_utc_str: str) -> list[ScanSchedule]:
        with self._session_factory() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = (
                select(ScheduleORM)
                .where(ScheduleORM.deleted_at.is_(None))
                .where(ScheduleORM.enabled == True)  # noqa: E712
                .where(ScheduleORM.paused == False)  # noqa: E712
                .where((ScheduleORM.next_run.is_(None)) | (ScheduleORM.next_run <= now_utc_str))
                .order_by(ScheduleORM.created_at)
            )
            return [self._to_domain(orm) for orm in session.execute(stmt).scalars().all()]

    def delete(self, schedule_id: str) -> None:
        """Tombstone the schedule (KSEC-88-03) rather than physically
        removing its row - see save()'s own docstring for why a hard
        delete left an unresolvable ambiguity for a stale write racing
        this call. Deliberately unconditional (no version check), exactly
        matching the pre-existing, already-tested behavior
        (test_schedule_repository.py's Scenario B): whoever calls
        delete() wins outright, regardless of which version they last
        read. Idempotent - a second delete() finds no live row (the
        ``deleted_at IS NULL`` filter already excludes it) and is a
        no-op, same as the old "already gone" case.
        """
        with self._session_factory.begin() as session:
            from kingsec.infrastructure.persistence.models import ScheduleORM

            stmt = select(ScheduleORM).where(ScheduleORM.id == schedule_id, ScheduleORM.deleted_at.is_(None))
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is not None:
                orm.deleted_at = datetime.now(UTC).isoformat()

    @staticmethod
    def _to_domain(orm: object) -> ScanSchedule:
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
            version=o.version,
        )

    @staticmethod
    def _field_values(s: ScanSchedule) -> dict[str, object]:
        """The mutable column values for *s*, as a plain dict - used for the
        Core ``update()`` statement in ``save()``'s optimistic-locked path.
        Deliberately a separate, flat mapping from ``_update_orm`` below
        (some duplication) rather than a shared helper: this dict feeds a
        Core statement while ``_update_orm`` mutates an ORM instance
        in-place for the insert path, and keeping them independent avoids
        entangling the two very different call shapes for a handful of
        field names."""
        return {
            "name": s.name,
            "description": s.description,
            "owner_user_id": s.owner_user_id,
            "target": s.target,
            "scanner_ids": list(s.scanner_ids),
            "config": dict(s.config),
            "schedule_type": s.schedule_type.value,
            "cron_expression": s.cron_expression,
            "timezone": s.timezone,
            "enabled": s.enabled,
            "paused": s.paused,
            "created_at": s.created_at,
            "updated_at": s.updated_at,
            "last_run": s.last_run,
            "next_run": s.next_run,
            "retry_strategy": s.retry_policy.strategy.value,
            "max_retries": s.retry_policy.max_retries,
            "retry_delay_seconds": s.retry_policy.retry_delay_seconds,
            "current_retry_count": s.current_retry_count,
            "status": s.status.value,
        }

    @staticmethod
    def _update_orm(orm: object, s: ScanSchedule) -> None:
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
