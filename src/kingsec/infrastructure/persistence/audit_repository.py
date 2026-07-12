"""SQLAlchemy audit trail repository — append-only persistence.

Implements the ``AuditPublisher`` port using SQLAlchemy. The repository
provides only ``record()`` (append) and ``list()`` (query) — there are
no update or delete methods. This is an architectural invariant: the
audit trail is immutable.

The repository uses autocommit per call, matching the pattern of the
existing assessment and user repositories.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.domain.audit import AuditEntry
from kingsec.infrastructure.logging import get_logger
from kingsec.shared.errors import PersistenceError, log_exception

from .models import AuditEntryORM

_logger = get_logger("kingsec.infrastructure.persistence.audit")


class SqlAlchemyAuditRepository(AuditPublisher):
    """Append-only audit trail backed by SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(self, entry: AuditEntry) -> None:
        """Append an audit entry to the trail.

        Args:
            entry: The immutable audit record to persist.

        Raises:
            PersistenceError: If the database operation fails.
        """
        try:
            with self._session_factory.begin() as session:
                orm = AuditEntryORM(
                    timestamp=entry.timestamp,
                    user_id=entry.user_id,
                    username=entry.username,
                    role=entry.role,
                    action=entry.action.value,
                    resource_type=entry.resource_type,
                    resource_id=entry.resource_id,
                    success=entry.success,
                    reason=entry.reason,
                    ip_address=entry.ip_address,
                    user_agent=entry.user_agent,
                    correlation_id=entry.correlation_id,
                    metadata_json=json.dumps(entry.metadata) if entry.metadata else "{}",
                )
                session.add(orm)
            _logger.debug(
                "audit entry recorded",
                action=entry.action.value,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                success=entry.success,
            )
        except SQLAlchemyError as exc:
            error = PersistenceError(
                "failed to record audit entry",
                context={"action": entry.action.value},
                cause=exc,
            )
            log_exception(_logger, error)
            raise error

    def list_entries(
        self,
        *,
        user_id: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
        success_only: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters.

        Args:
            user_id: Filter by user ID.
            action: Filter by action type.
            resource_type: Filter by resource type.
            since: Filter entries after this timestamp (ISO-8601).
            until: Filter entries before this timestamp (ISO-8601).
            success_only: If True, only successful entries; if False, only failures.
            limit: Maximum results (clamped to 200).
            offset: Results to skip.

        Returns:
            A list of audit entries, most recent first. May be empty.
        """
        clamped_limit = min(max(limit, 1), 200)
        try:
            with self._session_factory() as session:
                stmt = select(AuditEntryORM).order_by(AuditEntryORM.timestamp.desc())

                if user_id:
                    stmt = stmt.where(AuditEntryORM.user_id == user_id)
                if action:
                    stmt = stmt.where(AuditEntryORM.action == action)
                if resource_type:
                    stmt = stmt.where(AuditEntryORM.resource_type == resource_type)
                if since:
                    stmt = stmt.where(AuditEntryORM.timestamp >= since)
                if until:
                    stmt = stmt.where(AuditEntryORM.timestamp <= until)
                if success_only is not None:
                    stmt = stmt.where(AuditEntryORM.success == success_only)

                stmt = stmt.offset(max(offset, 0)).limit(clamped_limit)
                orms = session.execute(stmt).scalars().all()
                return [_to_domain(o) for o in orms]
        except SQLAlchemyError as exc:
            error = PersistenceError(
                "failed to query audit entries",
                context={"user_id": user_id, "action": action},
                cause=exc,
            )
            log_exception(_logger, error)
            raise error

    def count_entries(
        self,
        *,
        user_id: str | None = None,
        action: str | None = None,
    ) -> int:
        """Count audit entries with optional filters.

        Args:
            user_id: Filter by user ID.
            action: Filter by action type.

        Returns:
            The total count of matching entries.
        """
        from sqlalchemy import func

        try:
            with self._session_factory() as session:
                stmt = select(func.count()).select_from(AuditEntryORM)
                if user_id:
                    stmt = stmt.where(AuditEntryORM.user_id == user_id)
                if action:
                    stmt = stmt.where(AuditEntryORM.action == action)
                count = session.execute(stmt).scalar()
                return count if count else 0
        except SQLAlchemyError as exc:
            error = PersistenceError(
                "failed to count audit entries",
                context={"user_id": user_id, "action": action},
                cause=exc,
            )
            log_exception(_logger, error)
            raise error


def _to_domain(orm: AuditEntryORM) -> AuditEntry:
    """Convert an AuditEntryORM row to a domain AuditEntry value object."""
    from kingsec.domain.audit import AuditAction

    try:
        action = AuditAction(orm.action)
    except ValueError:
        action = AuditAction.LOGIN  # fallback for unknown actions

    metadata = {}
    if orm.metadata_json and orm.metadata_json != "{}":
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            metadata = {}

    return AuditEntry(
        action=action,
        resource_type=orm.resource_type,
        resource_id=orm.resource_id,
        success=orm.success,
        reason=orm.reason,
        timestamp=orm.timestamp,
        user_id=orm.user_id,
        username=orm.username,
        role=orm.role,
        ip_address=orm.ip_address,
        user_agent=orm.user_agent,
        correlation_id=orm.correlation_id,
        metadata=metadata,
    )
