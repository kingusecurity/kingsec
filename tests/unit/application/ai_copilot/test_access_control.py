"""Access-control tests for AI Copilot conversations and investigation notes.

Conversations/notes belong to the user who created them. A non-owner,
non-admin user must not be able to read, list, search, delete, or export
another user's conversation or note. Admins bypass the ownership check.
"""

from __future__ import annotations

from typing import Any

import pytest

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai_copilot.context_builder import CopilotContextBuilder
from kingsec.application.ai_copilot.copilot_service import CopilotService
from kingsec.application.ai_copilot.export_service import CopilotExportService
from kingsec.application.ai_copilot.notes_service import InvestigationNotesService
from kingsec.application.ai_copilot.ports import (
    CopilotConversationRepositoryPort,
    InvestigationNoteRepositoryPort,
)
from kingsec.application.errors import CopilotConversationNotFoundError, InvestigationNoteNotFoundError
from kingsec.domain.copilot import CopilotConversation, InvestigationNote


class FakeConversationRepo(CopilotConversationRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, CopilotConversation] = {}

    def save(self, conversation: CopilotConversation) -> CopilotConversation:
        self._store[conversation.id] = conversation
        return conversation

    def find_by_id(self, conversation_id: str) -> CopilotConversation | None:
        return self._store.get(conversation_id)

    def find_all(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        limit: int = 50,
    ) -> list[CopilotConversation]:
        return list(self._store.values())[:limit]

    def search(self, query: str, limit: int = 20) -> list[CopilotConversation]:
        return [c for c in self._store.values() if query.lower() in c.title.lower()][:limit]

    def delete(self, conversation_id: str) -> None:
        self._store.pop(conversation_id, None)


class FakeNoteRepo(InvestigationNoteRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, InvestigationNote] = {}

    def save(self, note: InvestigationNote) -> InvestigationNote:
        self._store[note.id] = note
        return note

    def find_by_id(self, note_id: str) -> InvestigationNote | None:
        return self._store.get(note_id)

    def find_by_conversation(self, conversation_id: str) -> list[InvestigationNote]:
        return [n for n in self._store.values() if n.conversation_id == conversation_id]

    def find_pinned(self, limit: int = 20) -> list[InvestigationNote]:
        return [n for n in self._store.values() if n.pinned][:limit]

    def find_all(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 50,
    ) -> list[InvestigationNote]:
        return list(self._store.values())[:limit]

    def delete(self, note_id: str) -> None:
        self._store.pop(note_id, None)


class FakeAI(AIQueryPort):
    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        return "fake answer"

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        return "fake answer"

    def health(self) -> dict[str, Any]:
        return {"status": "ok"}


@pytest.fixture
def conversation_repo() -> FakeConversationRepo:
    return FakeConversationRepo()


@pytest.fixture
def note_repo() -> FakeNoteRepo:
    return FakeNoteRepo()


@pytest.fixture
def copilot(conversation_repo: FakeConversationRepo) -> CopilotService:
    return CopilotService(
        ai=FakeAI(),
        context_builder=CopilotContextBuilder(),
        conversation_repo=conversation_repo,
    )


@pytest.fixture
def notes_service(note_repo: FakeNoteRepo) -> InvestigationNotesService:
    return InvestigationNotesService(note_repo=note_repo)


@pytest.fixture
def export_service(conversation_repo: FakeConversationRepo, note_repo: FakeNoteRepo) -> CopilotExportService:
    return CopilotExportService(
        conversation_repo=conversation_repo,
        note_repo=note_repo,
        context_builder=CopilotContextBuilder(),
    )


class TestConversationAccessControl:
    def test_owner_can_get_own_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        fetched = copilot.get_conversation(conv.id, requesting_user="alice", is_admin=False)
        assert fetched.id == conv.id

    def test_non_owner_cannot_get_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        with pytest.raises(CopilotConversationNotFoundError):
            copilot.get_conversation(conv.id, requesting_user="bob", is_admin=False)

    def test_admin_can_get_any_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        fetched = copilot.get_conversation(conv.id, requesting_user="admin", is_admin=True)
        assert fetched.id == conv.id

    def test_non_owner_cannot_delete_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        with pytest.raises(CopilotConversationNotFoundError):
            copilot.delete_conversation(conv.id, requesting_user="bob", is_admin=False)

    def test_owner_can_delete_own_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        copilot.delete_conversation(conv.id, requesting_user="alice", is_admin=False)
        with pytest.raises(CopilotConversationNotFoundError):
            copilot.get_conversation(conv.id, requesting_user="alice", is_admin=False)

    def test_list_conversations_filters_to_owner(self, copilot: CopilotService) -> None:
        copilot.create_conversation(title="Alice one", owner="alice")
        copilot.create_conversation(title="Bob one", owner="bob")
        result = copilot.list_conversations(requesting_user="alice", is_admin=False)
        assert [c.title for c in result] == ["Alice one"]

    def test_list_conversations_admin_sees_all(self, copilot: CopilotService) -> None:
        copilot.create_conversation(title="Alice one", owner="alice")
        copilot.create_conversation(title="Bob one", owner="bob")
        result = copilot.list_conversations(requesting_user="admin", is_admin=True)
        assert {c.title for c in result} == {"Alice one", "Bob one"}

    def test_search_conversations_filters_to_owner(self, copilot: CopilotService) -> None:
        copilot.create_conversation(title="shared keyword alice", owner="alice")
        copilot.create_conversation(title="shared keyword bob", owner="bob")
        result = copilot.search_conversations("shared keyword", requesting_user="alice", is_admin=False)
        assert [c.owner for c in result] == ["alice"]

    def test_legacy_conversation_with_no_owner_is_admin_only(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="legacy, no owner")
        with pytest.raises(CopilotConversationNotFoundError):
            copilot.get_conversation(conv.id, requesting_user="alice", is_admin=False)
        fetched = copilot.get_conversation(conv.id, requesting_user="admin", is_admin=True)
        assert fetched.id == conv.id

    def test_non_owner_cannot_ask_on_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        with pytest.raises(CopilotConversationNotFoundError):
            copilot.ask(conv.id, "what is this?", requesting_user="bob", is_admin=False)

    def test_owner_can_ask_on_own_conversation(self, copilot: CopilotService) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        result = copilot.ask(conv.id, "what is this?", requesting_user="alice", is_admin=False)
        assert result["answer"] == "fake answer"


class TestNoteAccessControl:
    def test_non_author_cannot_get_note(self, notes_service: InvestigationNotesService) -> None:
        note = notes_service.create_note(conversation_id="c1", content="secret", author="alice")
        with pytest.raises(InvestigationNoteNotFoundError):
            notes_service.get_note(note.id, requesting_user="bob", is_admin=False)

    def test_author_can_get_own_note(self, notes_service: InvestigationNotesService) -> None:
        note = notes_service.create_note(conversation_id="c1", content="secret", author="alice")
        fetched = notes_service.get_note(note.id, requesting_user="alice", is_admin=False)
        assert fetched.id == note.id

    def test_admin_can_get_any_note(self, notes_service: InvestigationNotesService) -> None:
        note = notes_service.create_note(conversation_id="c1", content="secret", author="alice")
        fetched = notes_service.get_note(note.id, requesting_user="admin", is_admin=True)
        assert fetched.id == note.id

    def test_non_author_cannot_update_note(self, notes_service: InvestigationNotesService) -> None:
        note = notes_service.create_note(conversation_id="c1", content="secret", author="alice")
        with pytest.raises(InvestigationNoteNotFoundError):
            notes_service.update_note(note.id, "tampered", requesting_user="bob", is_admin=False)

    def test_non_author_cannot_delete_note(self, notes_service: InvestigationNotesService) -> None:
        note = notes_service.create_note(conversation_id="c1", content="secret", author="alice")
        with pytest.raises(InvestigationNoteNotFoundError):
            notes_service.delete_note(note.id, requesting_user="bob", is_admin=False)

    def test_non_author_cannot_pin_or_unpin_note(self, notes_service: InvestigationNotesService) -> None:
        note = notes_service.create_note(conversation_id="c1", content="secret", author="alice")
        with pytest.raises(InvestigationNoteNotFoundError):
            notes_service.pin_note(note.id, requesting_user="bob", is_admin=False)
        with pytest.raises(InvestigationNoteNotFoundError):
            notes_service.unpin_note(note.id, requesting_user="bob", is_admin=False)

    def test_list_notes_filters_to_author(self, notes_service: InvestigationNotesService) -> None:
        notes_service.create_note(conversation_id="c1", content="alice's note", author="alice")
        notes_service.create_note(conversation_id="c2", content="bob's note", author="bob")
        result = notes_service.list_notes(requesting_user="alice", is_admin=False)
        assert [n.author for n in result] == ["alice"]

    def test_list_notes_admin_sees_all(self, notes_service: InvestigationNotesService) -> None:
        notes_service.create_note(conversation_id="c1", content="alice's note", author="alice")
        notes_service.create_note(conversation_id="c2", content="bob's note", author="bob")
        result = notes_service.list_notes(requesting_user="admin", is_admin=True)
        assert {n.author for n in result} == {"alice", "bob"}


class TestExportAccessControl:
    def test_non_owner_cannot_export_markdown(
        self, copilot: CopilotService, export_service: CopilotExportService
    ) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        md = export_service.export_markdown(conv.id, requesting_user="bob", is_admin=False)
        assert "Not Found" in md

    def test_owner_can_export_markdown(
        self, copilot: CopilotService, export_service: CopilotExportService
    ) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        md = export_service.export_markdown(conv.id, requesting_user="alice", is_admin=False)
        assert "Alice's investigation" in md

    def test_non_owner_cannot_export_json(
        self, copilot: CopilotService, export_service: CopilotExportService
    ) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        result = export_service.export_json(conv.id, requesting_user="bob", is_admin=False)
        assert "error" in result

    def test_admin_can_export_any_conversation(
        self, copilot: CopilotService, export_service: CopilotExportService
    ) -> None:
        conv = copilot.create_conversation(title="Alice's investigation", owner="alice")
        result = export_service.export_json(conv.id, requesting_user="admin", is_admin=True)
        assert result["conversation"]["id"] == conv.id
