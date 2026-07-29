from __future__ import annotations

import logging
from typing import Any

from kingsec.domain.playbook import (
    ActionExecutionLog,
    ExecutionHistory,
    ExecutionStatus,
    Playbook,
    PlaybookTrigger,
)

from .actions import ActionExecutor
from .ports import ExecutionHistoryRepositoryPort, PlaybookAuditPort

logger = logging.getLogger(__name__)


class PlaybookEngine:
    def __init__(
        self,
        history_repo: ExecutionHistoryRepositoryPort,
        action_executor: ActionExecutor,
        audit: PlaybookAuditPort | None = None,
    ) -> None:
        self._history_repo = history_repo
        self._action_executor = action_executor
        self._audit = audit

    def validate(self, playbook: Playbook) -> list[str]:
        errors: list[str] = []
        if not playbook.name.strip():
            errors.append("Playbook name is required")
        if not playbook.actions:
            errors.append("Playbook must have at least one action")
        if not playbook.trigger:
            errors.append("Playbook must have a trigger")
        return errors

    def evaluate_trigger(self, playbook: Playbook, event: dict[str, Any]) -> bool:
        if not playbook.enabled:
            return False
        if not playbook.trigger:
            return False
        return playbook.trigger.matches(event)

    def execute(
        self,
        playbook: Playbook,
        trigger_entity_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> ExecutionHistory:
        ctx = dict(context or {})
        errors = self.validate(playbook)
        if errors:
            history = ExecutionHistory.create(
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                trigger_type=playbook.trigger.trigger_type.value if playbook.trigger else "manual",
                trigger_entity_id=trigger_entity_id,
            )
            result = history.mark_failed("; ".join(errors), [])
            self._history_repo.save(result)
            self._audit_play("execution_failed", playbook.id, result)
            return result

        history = ExecutionHistory.create(
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            trigger_type=playbook.trigger.trigger_type.value if playbook.trigger else "manual",
            trigger_entity_id=trigger_entity_id,
        )
        ctx["execution_id"] = history.id
        ctx["playbook_id"] = playbook.id
        ctx["playbook_name"] = playbook.name
        ctx["trigger_entity_id"] = trigger_entity_id

        history = history.mark_running()
        self._history_repo.save(history)
        self._audit_play("execution_started", playbook.id, history)

        logs: list[ActionExecutionLog] = []
        overall_error = ""

        for action in playbook.actions:
            log = self._execute_with_retry(action, ctx)
            logs.append(log)
            if log.status == "failed" and not action.continue_on_failure:
                overall_error = f"Action '{action.action_type.value}' failed: {log.error}"
                break

        failed = any(l.status == "failed" for l in logs)

        if failed:
            history = history.mark_failed(overall_error, logs)
            if playbook.rollback_actions:
                self._rollback(history, playbook, ctx)
        else:
            history = history.mark_completed(logs)

        self._history_repo.save(history)
        if failed:
            self._audit_play("execution_failed", playbook.id, history)
        else:
            self._audit_play("execution_completed", playbook.id, history)
        return history

    def _execute_with_retry(
        self,
        action: Any,
        ctx: dict[str, Any],
    ) -> ActionExecutionLog:
        attempts = 0
        while attempts <= action.retry_count:
            log = self._action_executor.execute(action, ctx)
            if log.status == "completed":
                return log
            attempts += 1
            if attempts <= action.retry_count:
                import time
                time.sleep(1)
        return ActionExecutionLog(
            action_type=action.action_type.value,
            status="failed",
            error=f"Failed after {action.retry_count + 1} attempt(s)",
            retry_attempts=action.retry_count,
        )

    def _rollback(
        self,
        history: ExecutionHistory,
        playbook: Playbook,
        ctx: dict[str, Any],
    ) -> None:
        logger.info("Rolling back playbook %s (%s)", playbook.name, playbook.id)
        roll_logs: list[ActionExecutionLog] = []
        for action in playbook.rollback_actions:
            log = self._action_executor.execute(action, ctx)
            roll_logs.append(log)

        rolled = history.mark_rolled_back()
        self._history_repo.save(rolled)
        self._audit_play("rollback_completed", playbook.id, rolled)
        logger.info("Rollback complete for %s", playbook.name)

    def _audit_play(self, event_type: str, playbook_id: str, history: ExecutionHistory) -> None:
        if self._audit:
            try:
                self._audit.publish(f"playbook.{event_type}", {
                    "playbook_id": playbook_id,
                    "execution_id": history.id,
                    "status": history.status.value,
                    "rolled_back": history.rolled_back,
                })
            except Exception:
                logger.exception("Audit publish failed")
