"""SQLAlchemy enterprise audit event repository — append-only persistence.

Implements the ``AuditEventRepository`` port. Append-only by contract:
no update or delete methods are exposed.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)
from kingsec.infrastructure.logging import get_logger
from kingsec.shared.errors import PersistenceError, log_exception

from .models import AuditEventORM

_logger = get_logger("kingsec.infrastructure.persistence.audit_event")


class SqlAlchemyAuditEventRepository(AuditEventRepository):
    """Append-only enterprise audit event store backed by SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, event: AuditEvent) -> None:
        try:
            with self._session_factory.begin() as session:
                orm = AuditEventORM(
                    id=str(event.id),
                    timestamp=event.timestamp,
                    actor_id=event.actor_id,
                    actor_type=event.actor_type,
                    username=event.username,
                    ip_address=event.ip_address,
                    user_agent=event.user_agent,
                    request_id=event.request_id,
                    action=event.action.value,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    outcome=event.outcome.value,
                    severity=event.severity.value,
                    message=event.message,
                    metadata_json=json.dumps(event.metadata) if event.metadata else "{}",
                )
                session.add(orm)
            _logger.debug(
                "audit event recorded",
                event_id=str(event.id),
                action=event.action.value,
            )
        except SQLAlchemyError as exc:
            error = PersistenceError(
                "failed to record audit event",
                context={"event_id": str(event.id)},
                cause=exc,
            )
            log_exception(_logger, error)
            raise error from exc

    def find_by_id(self, event_id: AuditEventId) -> AuditEvent | None:
        try:
            with self._session_factory() as session:
                stmt = select(AuditEventORM).where(AuditEventORM.id == event_id.value)
                orm = session.execute(stmt).scalar_one_or_none()
                return _to_domain(orm) if orm else None
        except SQLAlchemyError as exc:
            error = PersistenceError(
                "failed to find audit event",
                context={"event_id": str(event_id)},
                cause=exc,
            )
            log_exception(_logger, error)
            raise error from exc

    def search(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        outcome: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> tuple[list[AuditEvent], int]:
        clamped_limit = min(max(limit, 1), 200)
        try:
            with self._session_factory() as session:
                base = select(AuditEventORM)
                count_base = select(func.count()).select_from(AuditEventORM)

                if actor_id:
                    base = base.where(AuditEventORM.actor_id == actor_id)
                    count_base = count_base.where(AuditEventORM.actor_id == actor_id)
                if action:
                    base = base.where(AuditEventORM.action == action)
                    count_base = count_base.where(AuditEventORM.action == action)
                if severity:
                    base = base.where(AuditEventORM.severity == severity)
                    count_base = count_base.where(AuditEventORM.severity == severity)
                if outcome:
                    base = base.where(AuditEventORM.outcome == outcome)
                    count_base = count_base.where(AuditEventORM.outcome == outcome)
                if resource_type:
                    base = base.where(AuditEventORM.resource_type == resource_type)
                    count_base = count_base.where(AuditEventORM.resource_type == resource_type)
                if resource_id:
                    base = base.where(AuditEventORM.resource_id == resource_id)
                    count_base = count_base.where(AuditEventORM.resource_id == resource_id)
                if since:
                    base = base.where(AuditEventORM.timestamp >= since)
                    count_base = count_base.where(AuditEventORM.timestamp >= since)
                if until:
                    base = base.where(AuditEventORM.timestamp <= until)
                    count_base = count_base.where(AuditEventORM.timestamp <= until)

                total = session.execute(count_base).scalar() or 0

                sort_col = getattr(AuditEventORM, sort_by, AuditEventORM.timestamp)
                order = sort_col.asc() if sort_order == "asc" else sort_col.desc()
                base = base.order_by(order)
                base = base.offset(max(offset, 0)).limit(clamped_limit)

                orms = session.execute(base).scalars().all()
                return [_to_domain(o) for o in orms], total
        except SQLAlchemyError as exc:
            error = PersistenceError(
                "failed to search audit events",
                context={"action": action},
                cause=exc,
            )
            log_exception(_logger, error)
            raise error from exc


def _to_domain(orm: AuditEventORM) -> AuditEvent:
    try:
        action = AuditAction(orm.action)
    except ValueError:
        action = AuditAction.LOGIN_SUCCESS

    try:
        outcome = AuditOutcome(orm.outcome)
    except ValueError:
        outcome = AuditOutcome.SUCCESS

    try:
        severity = AuditSeverity(orm.severity)
    except ValueError:
        severity = AuditSeverity.INFO

    metadata = {}
    if orm.metadata_json and orm.metadata_json != "{}":
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            metadata = {}

    return AuditEvent(
        id=AuditEventId(orm.id),
        timestamp=orm.timestamp,
        actor_id=orm.actor_id,
        actor_type=orm.actor_type,
        username=orm.username,
        ip_address=orm.ip_address,
        user_agent=orm.user_agent,
        request_id=orm.request_id,
        action=action,
        resource_type=orm.resource_type,
        resource_id=orm.resource_id,
        outcome=outcome,
        severity=severity,
        message=orm.message,
        metadata=metadata,
    )
