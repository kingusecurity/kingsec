from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class CopilotMessage:
    role: str = "user"
    content: str = ""
    timestamp: str = ""


@dataclass(frozen=True, slots=True)
class CopilotConversation:
    id: str
    title: str = ""
    assessment_id: str | None = None
    finding_id: str | None = None
    asset_id: str | None = None
    cve_id: str | None = None
    alert_id: str | None = None
    exposure_id: str | None = None
    messages: tuple[CopilotMessage, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def create(
        cls,
        title: str = "New Investigation",
        assessment_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        alert_id: str | None = None,
        exposure_id: str | None = None,
    ) -> CopilotConversation:
        from uuid import uuid4
        now = datetime.now(UTC).isoformat()
        return cls(
            id=uuid4().hex,
            title=title,
            assessment_id=assessment_id,
            finding_id=finding_id,
            asset_id=asset_id,
            cve_id=cve_id,
            alert_id=alert_id,
            exposure_id=exposure_id,
            created_at=now,
            updated_at=now,
        )

    def add_message(self, role: str, content: str) -> CopilotConversation:
        msg = CopilotMessage(role=role, content=content, timestamp=datetime.now(UTC).isoformat())
        return CopilotConversation(
            id=self.id,
            title=self.title,
            assessment_id=self.assessment_id,
            finding_id=self.finding_id,
            asset_id=self.asset_id,
            cve_id=self.cve_id,
            alert_id=self.alert_id,
            exposure_id=self.exposure_id,
            messages=(*self.messages, msg),
            metadata=self.metadata,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )


@dataclass(frozen=True, slots=True)
class InvestigationNote:
    id: str
    conversation_id: str
    content: str = ""
    author: str = ""
    pinned: bool = False
    assessment_id: str | None = None
    finding_id: str | None = None
    tags: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def create(
        cls,
        conversation_id: str,
        content: str,
        author: str,
        assessment_id: str | None = None,
        finding_id: str | None = None,
    ) -> InvestigationNote:
        from uuid import uuid4
        now = datetime.now(UTC).isoformat()
        return cls(
            id=uuid4().hex,
            conversation_id=conversation_id,
            content=content,
            author=author,
            assessment_id=assessment_id,
            finding_id=finding_id,
            created_at=now,
            updated_at=now,
        )

    def pin(self) -> InvestigationNote:
        return InvestigationNote(
            id=self.id,
            conversation_id=self.conversation_id,
            content=self.content,
            author=self.author,
            pinned=True,
            assessment_id=self.assessment_id,
            finding_id=self.finding_id,
            tags=self.tags,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def unpin(self) -> InvestigationNote:
        return InvestigationNote(
            id=self.id,
            conversation_id=self.conversation_id,
            content=self.content,
            author=self.author,
            pinned=False,
            assessment_id=self.assessment_id,
            finding_id=self.finding_id,
            tags=self.tags,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    id: str
    name: str
    category: str = "general"
    system_prompt: str = ""
    user_prompt_template: str = ""
    description: str = ""
    is_builtin: bool = True
