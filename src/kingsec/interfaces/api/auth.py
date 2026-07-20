from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from kingsec.application.ports import TokenClaims, TokenExpiredError, TokenInvalidError
from kingsec.domain import Role
from kingsec.infrastructure.auth.jwt_service import JWTTokenService
from kingsec.infrastructure.config.loader import load_settings

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    user_id: str
    username: str
    role: Role
    claims: TokenClaims


@cache
def _get_token_service() -> JWTTokenService:
    settings = load_settings()
    return JWTTokenService(settings.jwt)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_service = _get_token_service()
    try:
        claims = token_service.verify_access_token(credentials.credentials)
    except (TokenExpiredError, TokenInvalidError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        role = Role[claims.role.upper()]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid role in token: {claims.role}",
        )

    return CurrentUser(
        user_id=claims.user_id,
        username=claims.username,
        role=role,
        claims=claims,
    )
