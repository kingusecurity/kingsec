from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.notification import NotificationTemplate


class TemplateRendererPort(ABC):
    @abstractmethod
    def render(self, template: NotificationTemplate, variables: dict[str, str]) -> tuple[str, str]:
        """Render a template with variables. Returns (subject, body)."""
        ...

    @abstractmethod
    def get_template(self, event_type: str, channel: str) -> NotificationTemplate | None:
        """Look up a template by event type and channel."""
        ...
