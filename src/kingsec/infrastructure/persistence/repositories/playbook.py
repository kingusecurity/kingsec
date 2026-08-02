from __future__ import annotations

import json
import logging
from collections.abc import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kingsec.domain.playbook import ExecutionHistory, ExecutionStatus, Playbook
from kingsec.infrastructure.persistence.mappers import (
    execution_history_to_domain,
    execution_history_to_orm,
    playbook_to_domain,
    playbook_to_orm,
)
from kingsec.infrastructure.persistence.models import ExecutionHistoryModel, PlaybookModel

logger = logging.getLogger(__name__)


class SQLAlchemyPlaybookRepository:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def save(self, playbook: Playbook) -> None:
        with self._session_factory() as session:
            orm = session.get(PlaybookModel, playbook.id)
            if orm:
                existing = orm
                existing.name = playbook.name
                existing.description = playbook.description
                existing.category = playbook.category
                existing.severity = playbook.severity
                existing.tags_json = json.dumps(list(playbook.tags))
                existing.enabled = playbook.enabled
                existing.trigger_json = json.dumps({
                    "trigger_type": playbook.trigger.trigger_type.value,
                    "config": playbook.trigger.config,
                    "conditions": playbook.trigger.conditions,
                })
                existing.actions_json = json.dumps([
                    {"action_type": a.action_type.value, "config": a.config, "order": a.order,
                     "timeout_seconds": a.timeout_seconds, "retry_count": a.retry_count,
                     "continue_on_failure": a.continue_on_failure}
                    for a in playbook.actions
                ])
                existing.rollback_actions_json = json.dumps([
                    {"action_type": a.action_type.value, "config": a.config, "order": a.order,
                     "timeout_seconds": a.timeout_seconds, "retry_count": a.retry_count,
                     "continue_on_failure": a.continue_on_failure}
                    for a in playbook.rollback_actions
                ])
                existing.updated_at = playbook.updated_at
            else:
                session.add(playbook_to_orm(playbook))
            session.commit()

    def find_by_id(self, playbook_id: str) -> Playbook | None:
        with self._session_factory() as session:
            stmt = select(PlaybookModel).where(PlaybookModel.id == playbook_id)
            orm = session.execute(stmt).scalar_one_or_none()
            return playbook_to_domain(orm) if orm else None

    def find_all(
        self,
        enabled: bool | None = None,
        category: str | None = None,
        trigger_type: str | None = None,
        severity: str | None = None,
    ) -> list[Playbook]:
        with self._session_factory() as session:
            stmt = select(PlaybookModel)
            if enabled is not None:
                stmt = stmt.where(PlaybookModel.enabled == enabled)
            if category:
                stmt = stmt.where(PlaybookModel.category == category)
            if severity:
                stmt = stmt.where(PlaybookModel.severity == severity)
            if trigger_type:
                stmt = stmt.where(
                    PlaybookModel.trigger_json.like(f'%"{trigger_type}"%')
                )
            stmt = stmt.order_by(PlaybookModel.name)
            rows = session.execute(stmt).scalars().all()
            return [playbook_to_domain(r) for r in rows]

    def delete(self, playbook_id: str) -> None:
        with self._session_factory() as session:
            orm = session.get(PlaybookModel, playbook_id)
            if orm:
                session.delete(orm)
                session.commit()

    def count(self) -> int:
        with self._session_factory() as session:
            stmt = select(func.count(PlaybookModel.id))
            return session.execute(stmt).scalar() or 0


class SQLAlchemyExecutionHistoryRepository:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def save(self, history: ExecutionHistory) -> None:
        with self._session_factory() as session:
            orm = session.get(ExecutionHistoryModel, history.id)
            if orm:
                existing = orm
                existing.status = history.status.value
                existing.completed_at = history.completed_at
                existing.duration_ms = history.duration_ms
                existing.error = history.error
                existing.rolled_back = history.rolled_back
                existing.action_logs_json = json.dumps([
                    {
                        "action_type": l.action_type, "status": l.status,
                        "started_at": l.started_at, "completed_at": l.completed_at,
                        "duration_ms": l.duration_ms, "output": l.output,
                        "error": l.error, "retry_attempts": l.retry_attempts,
                    }
                    for l in history.action_logs
                ])
            else:
                session.add(execution_history_to_orm(history))
            session.commit()

    def find_by_id(self, execution_id: str) -> ExecutionHistory | None:
        with self._session_factory() as session:
            stmt = select(ExecutionHistoryModel).where(ExecutionHistoryModel.id == execution_id)
            orm = session.execute(stmt).scalar_one_or_none()
            return execution_history_to_domain(orm) if orm else None

    def find_by_playbook_id(
        self, playbook_id: str, limit: int = 50, offset: int = 0
    ) -> list[ExecutionHistory]:
        with self._session_factory() as session:
            stmt = (
                select(ExecutionHistoryModel)
                .where(ExecutionHistoryModel.playbook_id == playbook_id)
                .order_by(ExecutionHistoryModel.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = session.execute(stmt).scalars().all()
            return [execution_history_to_domain(r) for r in rows]

    def find_all(
        self,
        status: str | None = None,
        trigger_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionHistory]:
        with self._session_factory() as session:
            stmt = select(ExecutionHistoryModel)
            if status:
                stmt = stmt.where(ExecutionHistoryModel.status == status)
            if trigger_type:
                stmt = stmt.where(ExecutionHistoryModel.trigger_type == trigger_type)
            stmt = stmt.order_by(ExecutionHistoryModel.created_at.desc()).offset(offset).limit(limit)
            rows = session.execute(stmt).scalars().all()
            return [execution_history_to_domain(r) for r in rows]

    def count(
        self,
        status: str | None = None,
        trigger_type: str | None = None,
    ) -> int:
        with self._session_factory() as session:
            stmt = select(func.count(ExecutionHistoryModel.id))
            if status:
                stmt = stmt.where(ExecutionHistoryModel.status == status)
            if trigger_type:
                stmt = stmt.where(ExecutionHistoryModel.trigger_type == trigger_type)
            return session.execute(stmt).scalar() or 0

    def count_by_status(self) -> dict[str, int]:
        with self._session_factory() as session:
            stmt = select(
                ExecutionHistoryModel.status,
                func.count(ExecutionHistoryModel.id),
            ).group_by(ExecutionHistoryModel.status)
            return {row[0]: row[1] for row in session.execute(stmt).all()}

    def recent(
        self, limit: int = 10, offset: int = 0
    ) -> list[ExecutionHistory]:
        with self._session_factory() as session:
            stmt = (
                select(ExecutionHistoryModel)
                .order_by(ExecutionHistoryModel.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = session.execute(stmt).scalars().all()
            return [execution_history_to_domain(r) for r in rows]

    def average_duration_ms(self) -> float:
        with self._session_factory() as session:
            stmt = select(func.avg(ExecutionHistoryModel.duration_ms)).where(
                ExecutionHistoryModel.status == ExecutionStatus.COMPLETED.value
            )
            val = session.execute(stmt).scalar()
            return float(val) if val else 0.0

    def success_rate(self) -> float:
        total = self.count()
        if total == 0:
            return 1.0
        completed = self.count(status=ExecutionStatus.COMPLETED.value)
        return completed / total
