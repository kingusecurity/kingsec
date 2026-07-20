from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.create_session import CreateSession
from kingsec.application.use_cases.list_user_sessions import ListUserSessions
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.application.use_cases.revoke_session import RevokeSession
from kingsec.application.use_cases.session_dto import (
    CreateSessionRequest,
    ListUserSessionsRequest,
    RevokeAllSessionsRequest,
    RevokeSessionRequest,
    SessionView,
    TerminateOtherSessionsRequest,
)
from kingsec.application.use_cases.terminate_other_sessions import (
    TerminateOtherSessions,
)
from kingsec.bootstrap.application import Application
from kingsec.domain.session import DeviceInfo

from . import schemas
from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


def _get_create_session_uc(request: Request):
    app: Application = request.app.state.kingsec_app
    return app.resolve(CreateSession)


def _get_list_sessions_uc(request: Request):
    app: Application = request.app.state.kingsec_app
    return app.resolve(ListUserSessions)


def _get_revoke_session_uc(request: Request):
    app: Application = request.app.state.kingsec_app
    return app.resolve(RevokeSession)


def _get_revoke_all_uc(request: Request):
    app: Application = request.app.state.kingsec_app
    return app.resolve(RevokeAllSessions)


def _get_terminate_other_uc(request: Request):
    app: Application = request.app.state.kingsec_app
    return app.resolve(TerminateOtherSessions)


def _get_session_repo(request: Request):
    app: Application = request.app.state.kingsec_app
    return app.resolve(SessionRepository)


@router.get("", response_model=list[SessionView])
async def list_sessions(
    current_user: CurrentUser = Depends(get_current_user),
    list_uc=Depends(_get_list_sessions_uc),
) -> list[SessionView]:
    req = ListUserSessionsRequest(user_id=current_user.user_id)
    result = list_uc.execute(req)
    return result.sessions


@router.get("/current", response_model=SessionView)
async def get_current_session(
    current_user: CurrentUser = Depends(get_current_user),
    repo=Depends(_get_session_repo),
) -> SessionView:
    session = repo.find_by_jti(current_user.claims.jti)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")
    return SessionView(
        id=str(session.id),
        user_id=session.user_id,
        session_type=session.session_type.value,
        jti=session.jti,
        issued_at=session.issued_at,
        expires_at=session.expires_at,
        last_activity=session.last_activity,
        client_ip=session.client_ip,
        user_agent=session.user_agent,
        device_name=session.device_info.device_name,
        platform=session.device_info.platform,
        browser=session.device_info.browser,
        status=session.status.value,
    )


@router.delete("/current", status_code=status.HTTP_204_NO_CONTENT)
async def logout_current(
    current_user: CurrentUser = Depends(get_current_user),
    revoke_uc=Depends(_get_revoke_session_uc),
    repo=Depends(_get_session_repo),
) -> None:
    session = repo.find_by_jti(current_user.claims.jti)
    if session:
        revoke_uc.execute(RevokeSessionRequest(session_id=str(session.id)))


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session_by_id(
    session_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    revoke_uc=Depends(_get_revoke_session_uc),
    repo=Depends(_get_session_repo),
) -> None:
    session = repo.find_by_id(session_id)
    if session and session.user_id != current_user.user_id:
        from .auth import require_admin
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="not authorized")
    revoke_uc.execute(RevokeSessionRequest(session_id=session_id))


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    current_user: CurrentUser = Depends(get_current_user),
    revoke_all_uc=Depends(_get_revoke_all_uc),
) -> None:
    req = RevokeAllSessionsRequest(user_id=current_user.user_id)
    revoke_all_uc.execute(req)


@router.post("/refresh", response_model=schemas.RefreshTokenResponse)
async def refresh_session(
    body: schemas.RefreshTokenBody,
    request: Request,
) -> schemas.RefreshTokenResponse:
    from kingsec.application.use_cases.refresh_session import RefreshSession
    from kingsec.application.use_cases.session_dto import RefreshSessionRequest as RLDTO
    from kingsec.application.ports import TokenService

    app: Application = request.app.state.kingsec_app
    token_svc: TokenService = app.resolve(TokenService)

    old_claims = token_svc.verify_refresh_token(body.refresh_token)
    if old_claims.token_type != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token type")

    new_access_token = token_svc.create_access_token(
        user_id=old_claims.user_id,
        username=old_claims.username,
        role=old_claims.role,
    )
    new_access_claims = token_svc.verify_access_token(new_access_token)
    new_refresh_token = token_svc.create_refresh_token(
        user_id=old_claims.user_id,
        username=old_claims.username,
        role=old_claims.role,
    )
    new_refresh_claims = token_svc.verify_refresh_token(new_refresh_token)

    refresh_uc = app.resolve(RefreshSession)
    rl_req = RLDTO(
        user_id=old_claims.user_id,
        old_refresh_jti=old_claims.jti,
        new_refresh_jti=new_refresh_claims.jti,
        new_access_jti=new_access_claims.jti,
    )
    rl_result = refresh_uc.execute(rl_req)

    if rl_result.replay_detected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="refresh token replay detected",
        )
    if not rl_result.valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session not found or expired",
        )

    return schemas.RefreshTokenResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=1800,
    )
