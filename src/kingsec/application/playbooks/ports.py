from __future__ import annotations

from typing import Any, Protocol

from kingsec.domain.playbook import ExecutionHistory, Playbook


class PlaybookRepositoryPort(Protocol):
    def save(self, playbook: Playbook) -> None:
        ...

    def find_by_id(self, playbook_id: str) -> Playbook | None:
        ...

    def find_all(
        self,
        enabled: bool | None = None,
        category: str | None = None,
        trigger_type: str | None = None,
        severity: str | None = None,
    ) -> list[Playbook]:
        ...

    def delete(self, playbook_id: str) -> None:
        ...

    def count(self) -> int:
        ...


class ExecutionHistoryRepositoryPort(Protocol):
    def save(self, history: ExecutionHistory) -> None:
        ...

    def find_by_id(self, execution_id: str) -> ExecutionHistory | None:
        ...

    def find_by_playbook_id(
        self, playbook_id: str, limit: int = 50, offset: int = 0
    ) -> list[ExecutionHistory]:
        ...

    def find_all(
        self,
        status: str | None = None,
        trigger_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionHistory]:
        ...

    def count(
        self,
        status: str | None = None,
        trigger_type: str | None = None,
    ) -> int:
        ...

    def count_by_status(self) -> dict[str, int]:
        ...

    def recent(
        self, limit: int = 10, offset: int = 0
    ) -> list[ExecutionHistory]:
        ...

    def average_duration_ms(self) -> float:
        ...

    def success_rate(self) -> float:
        ...


class PlaybookAuditPort(Protocol):
    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        ...


class NotificationPort(Protocol):
    def send_slack(self, message: str, channel: str = "") -> None:
        ...

    def send_teams(self, message: str, webhook_url: str = "") -> None:
        ...

    def send_email(self, to: list[str], subject: str, body: str) -> None:
        ...


class ExternalTicketingPort(Protocol):
    def create_jira_ticket(self, summary: str, description: str, project: str = "") -> str:
        ...

    def create_github_issue(self, repo: str, title: str, body: str) -> str:
        ...


class AssessmentPort(Protocol):
    def run_assessment(self, asset_id: str) -> str:
        ...


class AiCopilotPort(Protocol):
    def generate_summary(self, context: dict[str, Any]) -> str:
        ...


class SiemPort(Protocol):
    def export_event(self, event: dict[str, Any]) -> str:
        ...


class InvestigationNotePort(Protocol):
    def create_note(self, title: str, content: str, entity_type: str, entity_id: str) -> str:
        ...


class AssetPort(Protocol):
    def mark_critical(self, asset_id: str) -> None:
        ...


class AlertPort(Protocol):
    def change_status(self, alert_id: str, status: str) -> None:
        ...


class ReportGeneratorPort(Protocol):
    def generate(self, report_type: str, params: dict[str, Any]) -> str:
        ...
