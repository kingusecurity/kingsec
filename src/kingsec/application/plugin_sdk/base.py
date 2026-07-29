from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BasePlugin(ABC):
    id: str = ""
    name: str = ""
    version: str = "0.0.0"
    author: str = ""

    @abstractmethod
    def initialize(self, context: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def shutdown(self) -> None:
        ...

    def health_check(self) -> dict[str, Any]:
        return {"status": "healthy", "plugin": self.name, "version": self.version}


class ScannerPlugin(BasePlugin):
    @abstractmethod
    def scan(self, target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        ...


class AiPlugin(BasePlugin):
    @abstractmethod
    def process(self, prompt: str, context: dict[str, Any] | None = None) -> str:
        ...


class ReportPlugin(BasePlugin):
    @abstractmethod
    def generate(self, data: dict[str, Any], format: str = "pdf") -> bytes:
        ...


class IntegrationPlugin(BasePlugin):
    @abstractmethod
    def push(self, event: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def pull(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        ...


class ExportPlugin(BasePlugin):
    @abstractmethod
    def export(self, data: dict[str, Any], format: str) -> bytes:
        ...


class NotificationPlugin(BasePlugin):
    @abstractmethod
    def send(self, message: str, recipients: list[str], config: dict[str, Any] | None = None) -> dict[str, Any]:
        ...


class DashboardWidgetPlugin(BasePlugin):
    @abstractmethod
    def render(self, config: dict[str, Any]) -> dict[str, Any]:
        ...


class CompliancePlugin(BasePlugin):
    @abstractmethod
    def evaluate(self, framework: str, controls: list[dict[str, Any]]) -> dict[str, Any]:
        ...


class ThreatFeedPlugin(BasePlugin):
    @abstractmethod
    def fetch(self, since: str | None = None) -> list[dict[str, Any]]:
        ...


class AutomationActionPlugin(BasePlugin):
    @abstractmethod
    def execute(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        ...
