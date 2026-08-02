from __future__ import annotations

import asyncio
import logging
from typing import Any

from kingsec.application.errors import InvestigationNoteNotFoundError
from kingsec.domain.copilot import InvestigationNote

from .ports import AuditPublisherPort, InvestigationNoteRepositoryPort

logger = logging.getLogger(__name__)

# Fire-and-forget audit tasks: kept alive here because asyncio only holds a
# weak reference to scheduled tasks, so an unreferenced task can be garbage
# collected before it runs.
_pending_audit_tasks: set[asyncio.Task[None]] = set()


def _fire_audit(audit: AuditPublisherPort | None, action: str, entity_type: str, entity_id: str, metadata: dict[str, Any] | None = None) -> None:
    if audit is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    try:
        if loop is not None:
            task = loop.create_task(audit.publish(action, entity_type, entity_id, metadata))
            _pending_audit_tasks.add(task)
            task.add_done_callback(_on_audit_task_done)
        else:
            # Called from a synchronous route handler running in a worker
            # thread — there is no event loop to schedule a background task
            # onto, so publish inline instead.
            asyncio.run(audit.publish(action, entity_type, entity_id, metadata))
    except Exception:
        logger.warning("audit publish failed (best-effort)", exc_info=True)


def _on_audit_task_done(task: asyncio.Task[None]) -> None:
    _pending_audit_tasks.discard(task)
    if not task.cancelled() and task.exception() is not None:
        logger.exception("Audit publish failed", exc_info=task.exception())


def _can_access(author: str, requesting_user: str, is_admin: bool) -> bool:
    """Access rule for a note: its author, or an admin, may access it."""
    if is_admin:
        return True
    return bool(author) and author == requesting_user


class InvestigationNotesService:
    def __init__(
        self,
        note_repo: InvestigationNoteRepositoryPort,
        audit: AuditPublisherPort | None = None,
    ) -> None:
        self._note_repo = note_repo
        self._audit = audit

    def create_note(
        self,
        conversation_id: str,
        content: str,
        author: str,
        assessment_id: str | None = None,
        finding_id: str | None = None,
    ) -> InvestigationNote:
        note = InvestigationNote.create(
            conversation_id=conversation_id,
            content=content,
            author=author,
            assessment_id=assessment_id,
            finding_id=finding_id,
        )
        saved = self._note_repo.save(note)
        _fire_audit(self._audit, "note_created", "investigation_note", saved.id, {
            "conversation_id": conversation_id,
            "author": author,
        })
        return saved

    def update_note(
        self, note_id: str, content: str, requesting_user: str = "", is_admin: bool = False
    ) -> InvestigationNote:
        note = self._note_repo.find_by_id(note_id)
        if not note or not _can_access(note.author, requesting_user, is_admin):
            raise InvestigationNoteNotFoundError(f"Note {note_id} not found")
        updated = InvestigationNote(
            id=note.id,
            conversation_id=note.conversation_id,
            content=content,
            author=note.author,
            pinned=note.pinned,
            assessment_id=note.assessment_id,
            finding_id=note.finding_id,
            tags=note.tags,
            created_at=note.created_at,
            updated_at=note.updated_at,
        )
        return self._note_repo.save(updated)

    def get_note(self, note_id: str, requesting_user: str = "", is_admin: bool = False) -> InvestigationNote:
        note = self._note_repo.find_by_id(note_id)
        if not note or not _can_access(note.author, requesting_user, is_admin):
            raise InvestigationNoteNotFoundError(f"Note {note_id} not found")
        return note

    def list_notes(
        self,
        conversation_id: str | None = None,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        pinned_only: bool = False,
        limit: int = 50,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> list[InvestigationNote]:
        if pinned_only:
            notes = self._note_repo.find_pinned(limit)
        elif conversation_id:
            notes = self._note_repo.find_by_conversation(conversation_id)
        else:
            notes = self._note_repo.find_all(
                assessment_id=assessment_id,
                finding_id=finding_id,
                limit=limit,
            )
        if is_admin:
            return notes
        return [n for n in notes if _can_access(n.author, requesting_user, is_admin)]

    def pin_note(self, note_id: str, requesting_user: str = "", is_admin: bool = False) -> InvestigationNote:
        note = self._note_repo.find_by_id(note_id)
        if not note or not _can_access(note.author, requesting_user, is_admin):
            raise InvestigationNoteNotFoundError(f"Note {note_id} not found")
        pinned = note.pin()
        saved = self._note_repo.save(pinned)
        _fire_audit(self._audit, "note_pinned", "investigation_note", note_id, {})
        return saved

    def unpin_note(self, note_id: str, requesting_user: str = "", is_admin: bool = False) -> InvestigationNote:
        note = self._note_repo.find_by_id(note_id)
        if not note or not _can_access(note.author, requesting_user, is_admin):
            raise InvestigationNoteNotFoundError(f"Note {note_id} not found")
        unpinned = note.unpin()
        saved = self._note_repo.save(unpinned)
        _fire_audit(self._audit, "note_unpinned", "investigation_note", note_id, {})
        return saved

    def delete_note(self, note_id: str, requesting_user: str = "", is_admin: bool = False) -> None:
        note = self._note_repo.find_by_id(note_id)
        if not note or not _can_access(note.author, requesting_user, is_admin):
            raise InvestigationNoteNotFoundError(f"Note {note_id} not found")
        self._note_repo.delete(note_id)
        _fire_audit(self._audit, "note_deleted", "investigation_note", note_id, {})
