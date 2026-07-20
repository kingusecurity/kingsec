from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from kingsec.application.use_cases.validate_session import ValidateSession
from kingsec.application.use_cases.session_dto import ValidateSessionRequest
from kingsec.bootstrap.application import Application

from .auth import CurrentUser, get_current_user
from .dependencies import get_application


async def require_valid_session(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    app: Application = Depends(get_application),
) -> CurrentUser:
    validate_uc: ValidateSession = app.resolve(ValidateSession)
    req = ValidateSessionRequest(
        jti=current_user.claims.jti,
        user_id=current_user.user_id,
    )
    result = validate_uc.execute(req)
    if not result.valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session is invalid, expired, or has been revoked",
        )
    return current_user
