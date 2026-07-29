from __future__ import annotations

from typing import Any, Protocol

from ...domain.copilot import CopilotConversation, InvestigationNote, PromptTemplate


class CopilotConversationRepositoryPort(Protocol):
    def save(self, conversation: CopilotConversation) -> CopilotConversation:
        ...

    def find_by_id(self, conversation_id: str) -> CopilotConversation | None:
        ...

    def find_all(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        limit: int = 50,
    ) -> list[CopilotConversation]:
        ...

    def search(self, query: str, limit: int = 20) -> list[CopilotConversation]:
        ...

    def delete(self, conversation_id: str) -> None:
        ...


class InvestigationNoteRepositoryPort(Protocol):
    def save(self, note: InvestigationNote) -> InvestigationNote:
        ...

    def find_by_id(self, note_id: str) -> InvestigationNote | None:
        ...

    def find_by_conversation(self, conversation_id: str) -> list[InvestigationNote]:
        ...

    def find_pinned(self, limit: int = 20) -> list[InvestigationNote]:
        ...

    def find_all(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 50,
    ) -> list[InvestigationNote]:
        ...

    def delete(self, note_id: str) -> None:
        ...


class AuditPublisherPort(Protocol):
    async def publish(
        self,
        action: str,
        entity_type: str,
        entity_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        ...


class CacheServicePort(Protocol):
    async def get(self, key: str) -> Any | None:
        ...

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        ...

    async def exists(self, key: str) -> bool:
        ...
