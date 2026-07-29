from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class PlaybookTriggerType(StrEnum):
    CRITICAL_FINDING = "critical_finding"
    NEW_CVE = "new_cve"
    KEV_DETECTED = "kev_detected"
    ATTACK_SURFACE_EXPOSURE = "attack_surface_exposure"
    HIGH_RISK_ASSET = "high_risk_asset"
    MONITORING_ALERT = "monitoring_alert"
    ASSESSMENT_COMPLETED = "assessment_completed"
    MANUAL = "manual"


class PlaybookActionType(StrEnum):
    GENERATE_REPORT = "generate_report"
    NOTIFY_SLACK = "notify_slack"
    NOTIFY_TEAMS = "notify_teams"
    SEND_EMAIL = "send_email"
    CREATE_JIRA_TICKET = "create_jira_ticket"
    CREATE_GITHUB_ISSUE = "create_github_issue"
    RUN_ASSESSMENT = "run_assessment"
    RUN_AI_COPILOT_SUMMARY = "run_ai_copilot_summary"
    EXPORT_SIEM_EVENT = "export_siem_event"
    CREATE_INVESTIGATION_NOTE = "create_investigation_note"
    MARK_ASSET_CRITICAL = "mark_asset_critical"
    CHANGE_ALERT_STATUS = "change_alert_status"
    CUSTOM_WEBHOOK = "custom_webhook"


class ExecutionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIALLY_COMPLETED = "partially_completed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class PlaybookAction:
    action_type: PlaybookActionType
    config: dict[str, Any] = field(default_factory=dict)
    order: int = 0
    timeout_seconds: int = 60
    retry_count: int = 0
    continue_on_failure: bool = False

    def with_order(self, order: int) -> PlaybookAction:
        return PlaybookAction(
            action_type=self.action_type,
            config=self.config,
            order=order,
            timeout_seconds=self.timeout_seconds,
            retry_count=self.retry_count,
            continue_on_failure=self.continue_on_failure,
        )


@dataclass(frozen=True, slots=True)
class PlaybookTrigger:
    trigger_type: PlaybookTriggerType
    config: dict[str, Any] = field(default_factory=dict)
    conditions: dict[str, Any] = field(default_factory=dict)

    def matches(self, event: dict[str, Any]) -> bool:
        if self.trigger_type == PlaybookTriggerType.MANUAL:
            return True
        event_type = event.get("type", "")
        if event_type != self.trigger_type.value:
            return False
        for key, expected in self.conditions.items():
            actual = event.get(key)
            if actual != expected:
                return False
        return True


@dataclass(frozen=True, slots=True)
class ActionExecutionLog:
    action_type: str = ""
    status: str = "pending"
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    retry_attempts: int = 0


@dataclass(frozen=True, slots=True)
class ExecutionHistory:
    id: str
    playbook_id: str = ""
    playbook_name: str = ""
    trigger_type: str = ""
    trigger_entity_id: str = ""
    status: ExecutionStatus = ExecutionStatus.PENDING
    action_logs: tuple[ActionExecutionLog, ...] = ()
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    error: str = ""
    rolled_back: bool = False
    created_at: str = ""

    @classmethod
    def create(
        cls,
        playbook_id: str,
        playbook_name: str,
        trigger_type: str,
        trigger_entity_id: str = "",
    ) -> ExecutionHistory:
        from uuid import uuid4
        now = datetime.now(UTC).isoformat()
        return cls(
            id=uuid4().hex,
            playbook_id=playbook_id,
            playbook_name=playbook_name,
            trigger_type=trigger_type,
            trigger_entity_id=trigger_entity_id,
            started_at=now,
            created_at=now,
        )

    def mark_running(self) -> ExecutionHistory:
        return ExecutionHistory(
            id=self.id, playbook_id=self.playbook_id, playbook_name=self.playbook_name,
            trigger_type=self.trigger_type, trigger_entity_id=self.trigger_entity_id,
            status=ExecutionStatus.RUNNING,
            action_logs=self.action_logs,
            started_at=self.started_at, completed_at=self.completed_at,
            duration_ms=self.duration_ms, error=self.error,
            rolled_back=self.rolled_back, created_at=self.created_at,
        )

    def mark_completed(self, logs: list[ActionExecutionLog]) -> ExecutionHistory:
        now = datetime.now(UTC).isoformat()
        duration = self._calc_duration(self.started_at, now)
        return ExecutionHistory(
            id=self.id, playbook_id=self.playbook_id, playbook_name=self.playbook_name,
            trigger_type=self.trigger_type, trigger_entity_id=self.trigger_entity_id,
            status=ExecutionStatus.COMPLETED,
            action_logs=tuple(logs),
            started_at=self.started_at, completed_at=now,
            duration_ms=duration, error="",
            rolled_back=self.rolled_back, created_at=self.created_at,
        )

    def mark_failed(self, error: str, logs: list[ActionExecutionLog]) -> ExecutionHistory:
        now = datetime.now(UTC).isoformat()
        duration = self._calc_duration(self.started_at, now)
        all_failed = all(l.status == "failed" for l in logs) if logs else True
        status = ExecutionStatus.FAILED if all_failed else ExecutionStatus.PARTIALLY_COMPLETED
        return ExecutionHistory(
            id=self.id, playbook_id=self.playbook_id, playbook_name=self.playbook_name,
            trigger_type=self.trigger_type, trigger_entity_id=self.trigger_entity_id,
            status=status,
            action_logs=tuple(logs),
            started_at=self.started_at, completed_at=now,
            duration_ms=duration, error=error,
            rolled_back=self.rolled_back, created_at=self.created_at,
        )

    def mark_rolled_back(self) -> ExecutionHistory:
        now = datetime.now(UTC).isoformat()
        duration = self._calc_duration(self.started_at, now)
        return ExecutionHistory(
            id=self.id, playbook_id=self.playbook_id, playbook_name=self.playbook_name,
            trigger_type=self.trigger_type, trigger_entity_id=self.trigger_entity_id,
            status=ExecutionStatus.ROLLED_BACK,
            action_logs=self.action_logs,
            started_at=self.started_at, completed_at=now,
            duration_ms=duration, error=self.error,
            rolled_back=True, created_at=self.created_at,
        )

    @staticmethod
    def _calc_duration(start: str, end: str) -> int:
        try:
            from datetime import datetime as dt
            s = dt.fromisoformat(start)
            e = dt.fromisoformat(end)
            return int((e - s).total_seconds() * 1000)
        except Exception:
            return 0


class Playbook:
    def __init__(
        self,
        playbook_id: str,
        name: str,
        description: str = "",
        category: str = "general",
        severity: str = "medium",
        tags: list[str] | None = None,
        enabled: bool = True,
        trigger: PlaybookTrigger | None = None,
        actions: list[PlaybookAction] | None = None,
        rollback_actions: list[PlaybookAction] | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        now = created_at or datetime.now(UTC).isoformat()
        self._id = playbook_id
        self._name = name
        self._description = description
        self._category = category
        self._severity = severity
        self._tags = list(tags) if tags else []
        self._enabled = enabled
        self._trigger = trigger or PlaybookTrigger(PlaybookTriggerType.MANUAL)
        self._actions = list(actions) if actions else []
        self._rollback_actions = list(rollback_actions) if rollback_actions else []
        self._created_at = now
        self._updated_at = updated_at or now

    @classmethod
    def create(
        cls,
        name: str,
        description: str = "",
        category: str = "general",
        severity: str = "medium",
        trigger: PlaybookTrigger | None = None,
        actions: list[PlaybookAction] | None = None,
        rollback_actions: list[PlaybookAction] | None = None,
    ) -> Playbook:
        from uuid import uuid4
        ordered = [a.with_order(i) for i, a in enumerate(actions)] if actions else []
        roll_ordered = [a.with_order(i) for i, a in enumerate(rollback_actions)] if rollback_actions else []
        return cls(
            playbook_id=uuid4().hex,
            name=name,
            description=description,
            category=category,
            severity=severity,
            trigger=trigger,
            actions=ordered,
            rollback_actions=roll_ordered,
        )

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def category(self) -> str:
        return self._category

    @property
    def severity(self) -> str:
        return self._severity

    @property
    def tags(self) -> tuple[str, ...]:
        return tuple(self._tags)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def trigger(self) -> PlaybookTrigger:
        return self._trigger

    @property
    def actions(self) -> tuple[PlaybookAction, ...]:
        return tuple(self._actions)

    @property
    def rollback_actions(self) -> tuple[PlaybookAction, ...]:
        return tuple(self._rollback_actions)

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def updated_at(self) -> str:
        return self._updated_at

    def enable(self) -> Playbook:
        return Playbook(
            playbook_id=self._id, name=self._name, description=self._description,
            category=self._category, severity=self._severity, tags=self._tags,
            enabled=True, trigger=self._trigger, actions=self._actions,
            rollback_actions=self._rollback_actions,
            created_at=self._created_at,
        )

    def disable(self) -> Playbook:
        return Playbook(
            playbook_id=self._id, name=self._name, description=self._description,
            category=self._category, severity=self._severity, tags=self._tags,
            enabled=False, trigger=self._trigger, actions=self._actions,
            rollback_actions=self._rollback_actions,
            created_at=self._created_at,
        )

    def update(
        self,
        name: str | None = None,
        description: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        tags: list[str] | None = None,
        enabled: bool | None = None,
        trigger: PlaybookTrigger | None = None,
        actions: list[PlaybookAction] | None = None,
        rollback_actions: list[PlaybookAction] | None = None,
    ) -> Playbook:
        return Playbook(
            playbook_id=self._id,
            name=name or self._name,
            description=description if description is not None else self._description,
            category=category or self._category,
            severity=severity or self._severity,
            tags=list(tags) if tags is not None else self._tags,
            enabled=enabled if enabled is not None else self._enabled,
            trigger=trigger or self._trigger,
            actions=list(actions) if actions is not None else self._actions,
            rollback_actions=list(rollback_actions) if rollback_actions is not None else self._rollback_actions,
            created_at=self._created_at,
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Playbook) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Playbook({self._name!r}, enabled={self._enabled})"
