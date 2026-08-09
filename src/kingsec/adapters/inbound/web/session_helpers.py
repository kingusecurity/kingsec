"""Shared helper: create a session record for a completed login.

Used by every route that can complete a login and issue real access/
refresh tokens - plain /auth/login, and the MFA-completion routes
(/mfa/verify, /mfa/recovery). Takes the token/user primitives directly
rather than a specific response DTO, since the three completion paths
each return a different (but structurally similar) response type.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import Request

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

logger = logging.getLogger("kingsec.adapters.inbound.web.session_helpers")


def create_session_for_login(
    request: Request,
    *,
    user_id: str,
    access_token: str,
    refresh_token: str,
) -> None:
    """Best-effort: record a session so it shows up in GET /sessions and can
    be individually revoked. Never raises - a session-tracking failure must
    not fail the login it's recording.
    """
    try:
        app: Application = request.app.state.kingsec_app
        from kingsec.application.ports import TokenService
        from kingsec.application.use_cases.create_session import CreateSession
        from kingsec.application.use_cases.session_dto import CreateSessionRequest
        from kingsec.domain.session import DeviceInfo

        token_svc: TokenService = app.resolve(TokenService)
        access_claims = token_svc.verify_access_token(access_token)
        refresh_claims = token_svc.verify_refresh_token(refresh_token)

        ip = request.client.host if request.client else ""
        ua = request.headers.get("user-agent", "")

        create_uc: CreateSession = app.resolve(CreateSession)
        create_uc.execute(
            CreateSessionRequest(
                user_id=user_id,
                jti=access_claims.jti,
                refresh_jti=refresh_claims.jti,
                client_ip=ip,
                user_agent=ua,
                device_info=DeviceInfo(device_name="", platform="", browser=""),
            )
        )
    except Exception:
        logger.warning("Failed to create session for login", exc_info=True)
