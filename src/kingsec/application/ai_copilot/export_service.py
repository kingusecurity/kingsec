from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ...domain.copilot import CopilotConversation, InvestigationNote
from .context_builder import CopilotContextBuilder
from .ports import AuditPublisherPort, CacheServicePort, CopilotConversationRepositoryPort, InvestigationNoteRepositoryPort


class CopilotExportService:
    def __init__(
        self,
        conversation_repo: CopilotConversationRepositoryPort,
        note_repo: InvestigationNoteRepositoryPort,
        context_builder: CopilotContextBuilder,
        audit: AuditPublisherPort | None = None,
    ) -> None:
        self._conversation_repo = conversation_repo
        self._note_repo = note_repo
        self._context_builder = context_builder
        self._audit = audit

    def export_markdown(self, conversation_id: str) -> str:
        conv = self._conversation_repo.find_by_id(conversation_id)
        if not conv:
            return "# Investigation Not Found\n\nNo conversation found with that ID."
        notes = self._note_repo.find_by_conversation(conversation_id)
        return self._to_markdown(conv, notes)

    def export_json(self, conversation_id: str) -> dict[str, Any]:
        conv = self._conversation_repo.find_by_id(conversation_id)
        if not conv:
            return {"error": "Conversation not found"}
        notes = self._note_repo.find_by_conversation(conversation_id)
        return self._to_json(conv, notes)

    def _to_markdown(self, conv: CopilotConversation, notes: list[InvestigationNote]) -> str:
        lines: list[str] = []
        lines.append(f"# Investigation: {conv.title}")
        lines.append("")
        lines.append(f"**Created:** {conv.created_at}")
        lines.append(f"**Updated:** {conv.updated_at}")
        lines.append("")

        if conv.assessment_id:
            lines.append(f"**Assessment:** {conv.assessment_id}")
        if conv.finding_id:
            lines.append(f"**Finding:** {conv.finding_id}")
        if conv.asset_id:
            lines.append(f"**Asset:** {conv.asset_id}")
        if conv.cve_id:
            lines.append(f"**CVE:** {conv.cve_id}")
        lines.append("")

        lines.append("---")
        lines.append("## Conversation")
        lines.append("")

        for msg in conv.messages:
            if msg.role == "user":
                lines.append(f"### 👤 User ({msg.timestamp[:10]})")
            else:
                lines.append(f"### 🤖 Assistant ({msg.timestamp[:10]})")
            lines.append("")
            lines.append(msg.content)
            lines.append("")

        if notes:
            lines.append("---")
            lines.append("## Investigation Notes")
            lines.append("")
            for note in notes:
                pin = "📌 " if note.pinned else ""
                lines.append(f"### {pin}Note by {note.author} ({note.created_at[:10]})")
                lines.append("")
                lines.append(note.content)
                lines.append("")

        lines.append("---")
        lines.append(f"*Exported from KingSec on {datetime.now(UTC).isoformat()}*")
        return "\n".join(lines)

    def _to_json(self, conv: CopilotConversation, notes: list[InvestigationNote]) -> dict[str, Any]:
        return {
            "export_version": "1.0",
            "exported_at": datetime.now(UTC).isoformat(),
            "conversation": {
                "id": conv.id,
                "title": conv.title,
                "assessment_id": conv.assessment_id,
                "finding_id": conv.finding_id,
                "asset_id": conv.asset_id,
                "cve_id": conv.cve_id,
                "alert_id": conv.alert_id,
                "exposure_id": conv.exposure_id,
                "created_at": conv.created_at,
                "updated_at": conv.updated_at,
                "messages": [
                    {"role": m.role, "content": m.content, "timestamp": m.timestamp}
                    for m in conv.messages
                ],
            },
            "notes": [
                {
                    "id": n.id,
                    "author": n.author,
                    "content": n.content,
                    "pinned": n.pinned,
                    "created_at": n.created_at,
                    "updated_at": n.updated_at,
                }
                for n in notes
            ],
        }
