"""Bridges the AI Copilot's ``AuditPublisherPort`` onto the existing audit trail.

The AI Copilot subsystem defines its own small audit port
(``kingsec.application.ai_copilot.ports.AuditPublisherPort``) rather than
reusing the domain-wide ``AuditPublisher``. This adapter is the missing
link: it implements that port by translating each call into an
``AuditEntry`` on the same audit trail every other feature already writes
to, so Copilot and investigation-note actions actually get recorded.
"""

from __future__ import annotations

from typing import Any

from kingsec.application.ai_copilot.ports import AuditPublisherPort
from kingsec.application.ports.outbound import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry

_ACTION_MAP: dict[str, AuditAction] = {
    "copilot_ask": AuditAction.COPILOT_ASK,
    "copilot_delete": AuditAction.COPILOT_CONVERSATION_DELETED,
    "note_created": AuditAction.NOTE_CREATED,
    "note_pinned": AuditAction.NOTE_PINNED,
    "note_unpinned": AuditAction.NOTE_UNPINNED,
    "note_deleted": AuditAction.NOTE_DELETED,
}


class CopilotAuditAdapter(AuditPublisherPort):
    """Publishes AI Copilot audit events onto the domain-wide audit trail."""

    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit

    async def publish(
        self,
        action: str,
        entity_type: str,
        entity_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._audit.record(
            AuditEntry(
                action=_ACTION_MAP.get(action, AuditAction.COPILOT_ASK),
                resource_type=entity_type,
                resource_id=entity_id,
                success=True,
                metadata=metadata or {},
            )
        )
