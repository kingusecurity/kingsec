from __future__ import annotations

import logging
from typing import Any

from kingsec.domain.playbook import (
    ExecutionHistory,
    Playbook,
    PlaybookAction,
    PlaybookTrigger,
)

from .engine import PlaybookEngine
from .ports import ExecutionHistoryRepositoryPort, PlaybookAuditPort, PlaybookRepositoryPort

logger = logging.getLogger(__name__)


class PlaybookService:
    def __init__(
        self,
        playbook_repo: PlaybookRepositoryPort,
        engine: PlaybookEngine,
        history_repo: ExecutionHistoryRepositoryPort,
        audit: PlaybookAuditPort | None = None,
    ) -> None:
        self._playbook_repo = playbook_repo
        self._engine = engine
        self._history_repo = history_repo
        self._audit_port = audit

    def create_playbook(
        self,
        name: str,
        description: str = "",
        category: str = "general",
        severity: str = "medium",
        tags: list[str] | None = None,
        trigger: dict[str, Any] | None = None,
        actions: list[dict[str, Any]] | None = None,
        rollback_actions: list[dict[str, Any]] | None = None,
    ) -> Playbook:
        self._engine.validate(
            Playbook.create(name=name, description=description)
        )
        from uuid import uuid4
        playbook = Playbook(
            playbook_id=uuid4().hex,
            name=name,
            description=description,
            category=category,
            severity=severity,
            tags=tags or [],
            trigger=self._build_trigger(trigger) if trigger else None,
            actions=self._build_actions(actions) if actions else None,
            rollback_actions=self._build_actions(rollback_actions) if rollback_actions else None,
        )
        self._playbook_repo.save(playbook)
        self._publish_audit("playbook.created", {"playbook_id": playbook.id, "name": playbook.name})
        return playbook

    def get_playbook(self, playbook_id: str) -> Playbook | None:
        return self._playbook_repo.find_by_id(playbook_id)

    def list_playbooks(
        self,
        enabled: bool | None = None,
        category: str | None = None,
        trigger_type: str | None = None,
        severity: str | None = None,
    ) -> list[Playbook]:
        return self._playbook_repo.find_all(
            enabled=enabled,
            category=category,
            trigger_type=trigger_type,
            severity=severity,
        )

    def update_playbook(
        self,
        playbook_id: str,
        name: str | None = None,
        description: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        tags: list[str] | None = None,
        enabled: bool | None = None,
        trigger: dict[str, Any] | None = None,
        actions: list[dict[str, Any]] | None = None,
        rollback_actions: list[dict[str, Any]] | None = None,
    ) -> Playbook:
        existing = self._playbook_repo.find_by_id(playbook_id)
        if not existing:
            raise ValueError(f"Playbook {playbook_id} not found")
        updated = existing.update(
            name=name,
            description=description,
            category=category,
            severity=severity,
            tags=tags,
            enabled=enabled,
            trigger=self._build_trigger(trigger) if trigger is not None else None,
            actions=self._build_actions(actions) if actions is not None else None,
            rollback_actions=self._build_actions(rollback_actions) if rollback_actions is not None else None,
        )
        self._playbook_repo.save(updated)
        self._publish_audit("playbook.updated", {"playbook_id": playbook_id})
        return updated

    def delete_playbook(self, playbook_id: str) -> None:
        self._playbook_repo.delete(playbook_id)
        self._publish_audit("playbook.deleted", {"playbook_id": playbook_id})

    def enable_playbook(self, playbook_id: str) -> Playbook:
        existing = self._playbook_repo.find_by_id(playbook_id)
        if not existing:
            raise ValueError(f"Playbook {playbook_id} not found")
        updated = existing.enable()
        self._playbook_repo.save(updated)
        self._publish_audit("playbook.enabled", {"playbook_id": playbook_id})
        return updated

    def disable_playbook(self, playbook_id: str) -> Playbook:
        existing = self._playbook_repo.find_by_id(playbook_id)
        if not existing:
            raise ValueError(f"Playbook {playbook_id} not found")
        updated = existing.disable()
        self._playbook_repo.save(updated)
        self._publish_audit("playbook.disabled", {"playbook_id": playbook_id})
        return updated

    def execute_playbook(
        self,
        playbook_id: str,
        trigger_entity_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> ExecutionHistory:
        playbook = self._playbook_repo.find_by_id(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")
        return self._engine.execute(playbook, trigger_entity_id, context)

    def evaluate_and_trigger(
        self,
        event: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[ExecutionHistory]:
        enabled_playbooks = self._playbook_repo.find_all(enabled=True)
        results: list[ExecutionHistory] = []
        for pb in enabled_playbooks:
            if self._engine.evaluate_trigger(pb, event):
                result = self._engine.execute(pb, event.get("entity_id", ""), context)
                results.append(result)
        return results

    def get_execution(self, execution_id: str) -> ExecutionHistory | None:
        return self._history_repo.find_by_id(execution_id)

    def list_executions(
        self,
        status: str | None = None,
        trigger_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionHistory]:
        return self._history_repo.find_all(
            status=status,
            trigger_type=trigger_type,
            limit=limit,
            offset=offset,
        )

    def list_executions_by_playbook(
        self, playbook_id: str, limit: int = 50, offset: int = 0
    ) -> list[ExecutionHistory]:
        return self._history_repo.find_by_playbook_id(playbook_id, limit, offset)

    def get_history_stats(self) -> dict[str, Any]:
        by_status = self._history_repo.count_by_status()
        total = sum(by_status.values())
        success_rate = self._history_repo.success_rate()
        avg_duration = self._history_repo.average_duration_ms()
        recent = self._history_repo.recent(limit=5)
        return {
            "total_executions": total,
            "by_status": by_status,
            "success_rate": success_rate,
            "average_duration_ms": avg_duration,
            "recent_executions": [
                {
                    "id": h.id,
                    "playbook_name": h.playbook_name,
                    "status": h.status.value,
                    "started_at": h.started_at,
                    "duration_ms": h.duration_ms,
                }
                for h in recent
            ],
        }

    def get_playbook_count(self) -> int:
        return self._playbook_repo.count()

    @staticmethod
    def _build_trigger(data: dict[str, Any]) -> PlaybookTrigger:
        from kingsec.domain.playbook import PlaybookTriggerType
        return PlaybookTrigger(
            trigger_type=PlaybookTriggerType(data.get("trigger_type", "manual")),
            config=data.get("config", {}),
            conditions=data.get("conditions", {}),
        )

    @staticmethod
    def _build_actions(data_list: list[dict[str, Any]]) -> list[PlaybookAction]:
        from kingsec.domain.playbook import PlaybookActionType
        return [
            PlaybookAction(
                action_type=PlaybookActionType(a.get("action_type", "custom_webhook")),
                config=a.get("config", {}),
                order=a.get("order", i),
                timeout_seconds=a.get("timeout_seconds", 60),
                retry_count=a.get("retry_count", 0),
                continue_on_failure=a.get("continue_on_failure", False),
            )
            for i, a in enumerate(data_list)
        ]

    def _publish_audit(self, event_type: str, data: dict[str, Any]) -> None:
        if self._audit_port:
            try:
                self._audit_port.publish(event_type, data)
            except Exception:
                logger.exception("Audit publish failed for %s", event_type)
