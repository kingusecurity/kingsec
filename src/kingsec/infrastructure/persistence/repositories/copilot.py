from __future__ import annotations

from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from kingsec.application.ai_copilot.ports import (
    CopilotConversationRepositoryPort,
    InvestigationNoteRepositoryPort,
)
from kingsec.domain.copilot import CopilotConversation, InvestigationNote
from kingsec.infrastructure.persistence.mappers import (
    copilot_conversation_to_domain,
    copilot_conversation_to_orm,
    investigation_note_to_domain,
    investigation_note_to_orm,
)
from kingsec.infrastructure.persistence.models import CopilotConversationModel, InvestigationNoteModel


class SQLAlchemyCopilotConversationRepository(CopilotConversationRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, conversation: CopilotConversation) -> CopilotConversation:
        model = self._session.get(CopilotConversationModel, conversation.id)
        orm = copilot_conversation_to_orm(conversation)
        if model:
            for col in CopilotConversationModel.__table__.columns:
                setattr(model, col.name, getattr(orm, col.name))
        else:
            self._session.add(orm)
        self._session.flush()
        return conversation

    def find_by_id(self, conversation_id: str) -> CopilotConversation | None:
        model = self._session.get(CopilotConversationModel, conversation_id)
        return copilot_conversation_to_domain(model) if model else None

    def find_all(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        limit: int = 50,
    ) -> list[CopilotConversation]:
        q = self._session.query(CopilotConversationModel)
        if assessment_id:
            q = q.filter(CopilotConversationModel.assessment_id == assessment_id)
        if finding_id:
            q = q.filter(CopilotConversationModel.finding_id == finding_id)
        if asset_id:
            q = q.filter(CopilotConversationModel.asset_id == asset_id)
        if cve_id:
            q = q.filter(CopilotConversationModel.cve_id == cve_id)
        models = q.order_by(CopilotConversationModel.updated_at.desc()).limit(limit).all()
        return [copilot_conversation_to_domain(m) for m in models]

    def search(self, query: str, limit: int = 20) -> list[CopilotConversation]:
        models = self._session.query(CopilotConversationModel).filter(
            or_(
                CopilotConversationModel.title.ilike(f"%{query}%"),
                CopilotConversationModel.messages_json.ilike(f"%{query}%"),
            )
        ).order_by(CopilotConversationModel.updated_at.desc()).limit(limit).all()
        return [copilot_conversation_to_domain(m) for m in models]

    def delete(self, conversation_id: str) -> None:
        model = self._session.get(CopilotConversationModel, conversation_id)
        if model:
            self._session.delete(model)
            self._session.flush()


class SQLAlchemyInvestigationNoteRepository(InvestigationNoteRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, note: InvestigationNote) -> InvestigationNote:
        model = self._session.get(InvestigationNoteModel, note.id)
        orm = investigation_note_to_orm(note)
        if model:
            for col in InvestigationNoteModel.__table__.columns:
                setattr(model, col.name, getattr(orm, col.name))
        else:
            self._session.add(orm)
        self._session.flush()
        return note

    def find_by_id(self, note_id: str) -> InvestigationNote | None:
        model = self._session.get(InvestigationNoteModel, note_id)
        return investigation_note_to_domain(model) if model else None

    def find_by_conversation(self, conversation_id: str) -> list[InvestigationNote]:
        models = self._session.query(InvestigationNoteModel).filter(
            InvestigationNoteModel.conversation_id == conversation_id
        ).order_by(InvestigationNoteModel.created_at.desc()).all()
        return [investigation_note_to_domain(m) for m in models]

    def find_pinned(self, limit: int = 20) -> list[InvestigationNote]:
        models = self._session.query(InvestigationNoteModel).filter(
            InvestigationNoteModel.pinned == True
        ).order_by(InvestigationNoteModel.updated_at.desc()).limit(limit).all()
        return [investigation_note_to_domain(m) for m in models]

    def find_all(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 50,
    ) -> list[InvestigationNote]:
        q = self._session.query(InvestigationNoteModel)
        if assessment_id:
            q = q.filter(InvestigationNoteModel.assessment_id == assessment_id)
        if finding_id:
            q = q.filter(InvestigationNoteModel.finding_id == finding_id)
        models = q.order_by(InvestigationNoteModel.created_at.desc()).limit(limit).all()
        return [investigation_note_to_domain(m) for m in models]

    def delete(self, note_id: str) -> None:
        model = self._session.get(InvestigationNoteModel, note_id)
        if model:
            self._session.delete(model)
            self._session.flush()
