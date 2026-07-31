from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from kingsec.application.ai_copilot.copilot_service import CopilotService
from kingsec.application.ai_copilot.export_service import CopilotExportService
from kingsec.application.ai_copilot.notes_service import InvestigationNotesService
from kingsec.application.errors import CopilotConversationNotFoundError, InvestigationNoteNotFoundError

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1", tags=["AI Copilot"])


def _get_copilot(request: Request, _: CurrentUser = Depends(get_current_user)) -> CopilotService:
    app = get_application(request)
    return app.resolve(CopilotService)


def _get_notes(request: Request, _: CurrentUser = Depends(get_current_user)) -> InvestigationNotesService:
    app = get_application(request)
    return app.resolve(InvestigationNotesService)


def _get_export(request: Request, _: CurrentUser = Depends(get_current_user)) -> CopilotExportService:
    app = get_application(request)
    return app.resolve(CopilotExportService)


# --- Conversations ---


@router.post("/copilot/conversations")
def create_conversation(
    body: dict[str, Any],
    copilot: CopilotService = Depends(_get_copilot),
) -> dict[str, Any]:
    conv = copilot.create_conversation(
        title=body.get("title", "New Investigation"),
        assessment_id=body.get("assessment_id"),
        finding_id=body.get("finding_id"),
        asset_id=body.get("asset_id"),
        cve_id=body.get("cve_id"),
        alert_id=body.get("alert_id"),
        exposure_id=body.get("exposure_id"),
    )
    return _conv_to_dict(conv)


@router.get("/copilot/conversations")
def list_conversations(
    assessment_id: str | None = Query(None),
    finding_id: str | None = Query(None),
    asset_id: str | None = Query(None),
    cve_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    copilot: CopilotService = Depends(_get_copilot),
) -> list[dict[str, Any]]:
    convs = copilot.list_conversations(
        assessment_id=assessment_id,
        finding_id=finding_id,
        asset_id=asset_id,
        cve_id=cve_id,
        limit=limit,
    )
    return [_conv_to_dict(c) for c in convs]


@router.get("/copilot/conversations/search")
def search_conversations(
    q: str = Query(..., min_length=1),
    limit: int = Query(20, ge=1, le=100),
    copilot: CopilotService = Depends(_get_copilot),
) -> list[dict[str, Any]]:
    convs = copilot.search_conversations(q, limit)
    return [_conv_to_dict(c) for c in convs]


@router.get("/copilot/conversations/{conversation_id}")
def get_conversation(
    conversation_id: str,
    copilot: CopilotService = Depends(_get_copilot),
) -> dict[str, Any]:
    try:
        conv = copilot.get_conversation(conversation_id)
        return _conv_to_dict(conv)
    except CopilotConversationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/copilot/conversations/{conversation_id}")
def delete_conversation(
    conversation_id: str,
    copilot: CopilotService = Depends(_get_copilot),
) -> dict[str, str]:
    try:
        copilot.delete_conversation(conversation_id)
        return {"status": "deleted"}
    except CopilotConversationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --- Ask ---


@router.post("/copilot/ask")
def ask_copilot(
    body: dict[str, Any],
    copilot: CopilotService = Depends(_get_copilot),
) -> dict[str, Any]:
    conversation_id = body.get("conversation_id", "")
    question = body.get("question", "")
    template_id = body.get("template_id")
    if not conversation_id:
        raise HTTPException(status_code=400, detail="conversation_id is required")
    if not question:
        raise HTTPException(status_code=400, detail="question is required")
    try:
        return copilot.ask(conversation_id, question, template_id)
    except CopilotConversationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --- Prompt Templates ---


@router.get("/copilot/templates")
def list_templates(
    copilot: CopilotService = Depends(_get_copilot),
) -> list[dict[str, Any]]:
    return copilot.get_prompt_templates()


# --- Notes ---


@router.post("/copilot/notes")
def create_note(
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> dict[str, Any]:
    note = notes_svc.create_note(
        conversation_id=body.get("conversation_id", ""),
        content=body.get("content", ""),
        author=user.username,
        assessment_id=body.get("assessment_id"),
        finding_id=body.get("finding_id"),
    )
    return _note_to_dict(note)


@router.get("/copilot/notes")
def list_notes(
    conversation_id: str | None = Query(None),
    assessment_id: str | None = Query(None),
    finding_id: str | None = Query(None),
    pinned_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> list[dict[str, Any]]:
    notes = notes_svc.list_notes(
        conversation_id=conversation_id,
        assessment_id=assessment_id,
        finding_id=finding_id,
        pinned_only=pinned_only,
        limit=limit,
    )
    return [_note_to_dict(n) for n in notes]


@router.get("/copilot/notes/{note_id}")
def get_note(
    note_id: str,
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> dict[str, Any]:
    try:
        note = notes_svc.get_note(note_id)
        return _note_to_dict(note)
    except InvestigationNoteNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/copilot/notes/{note_id}")
def update_note(
    note_id: str,
    body: dict[str, Any],
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> dict[str, Any]:
    try:
        note = notes_svc.update_note(note_id, body.get("content", ""))
        return _note_to_dict(note)
    except InvestigationNoteNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/copilot/notes/{note_id}/pin")
def pin_note(
    note_id: str,
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> dict[str, Any]:
    try:
        note = notes_svc.pin_note(note_id)
        return _note_to_dict(note)
    except InvestigationNoteNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/copilot/notes/{note_id}/unpin")
def unpin_note(
    note_id: str,
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> dict[str, Any]:
    try:
        note = notes_svc.unpin_note(note_id)
        return _note_to_dict(note)
    except InvestigationNoteNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/copilot/notes/{note_id}")
def delete_note(
    note_id: str,
    notes_svc: InvestigationNotesService = Depends(_get_notes),
) -> dict[str, str]:
    try:
        notes_svc.delete_note(note_id)
        return {"status": "deleted"}
    except InvestigationNoteNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --- Export ---


@router.get("/copilot/export/{conversation_id}/markdown")
def export_markdown(
    conversation_id: str,
    export_svc: CopilotExportService = Depends(_get_export),
) -> dict[str, str]:
    md = export_svc.export_markdown(conversation_id)
    return {"markdown": md}


@router.get("/copilot/export/{conversation_id}/json")
def export_json(
    conversation_id: str,
    export_svc: CopilotExportService = Depends(_get_export),
) -> dict[str, Any]:
    return export_svc.export_json(conversation_id)


# --- Helpers ---


def _conv_to_dict(conv: Any) -> dict[str, Any]:
    return {
        "id": conv.id,
        "title": conv.title,
        "assessment_id": conv.assessment_id,
        "finding_id": conv.finding_id,
        "asset_id": conv.asset_id,
        "cve_id": conv.cve_id,
        "alert_id": conv.alert_id,
        "exposure_id": conv.exposure_id,
        "messages": [
            {"role": m.role, "content": m.content, "timestamp": m.timestamp}
            for m in conv.messages
        ],
        "created_at": conv.created_at,
        "updated_at": conv.updated_at,
    }


def _note_to_dict(note: Any) -> dict[str, Any]:
    return {
        "id": note.id,
        "conversation_id": note.conversation_id,
        "content": note.content,
        "author": note.author,
        "pinned": note.pinned,
        "assessment_id": note.assessment_id,
        "finding_id": note.finding_id,
        "tags": list(note.tags),
        "created_at": note.created_at,
        "updated_at": note.updated_at,
    }
