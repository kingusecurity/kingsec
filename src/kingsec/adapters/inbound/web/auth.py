"""FastAPI auth dependencies — resolve the current user from JWT Bearer tokens.

This module lives entirely inside the web adapter. It never leaks into the
application or domain layers. FastAPI's ``Depends()`` wires the dependency
at request time.

Security considerations:
    - Bearer token is extracted from the ``Authorization`` header.
    - Expired tokens return 401, invalid tokens return 401.
    - Missing/invalid roles return 403.
    - The dependency is reusable across all protected endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from kingsec.application.ports import TokenClaims, TokenService
from kingsec.bootstrap.application import Application
from kingsec.domain import Role

# Security scheme for OpenAPI docs.
bearer_scheme = HTTPBearer(auto_error=False)


def _get_token_service(request: Request) -> TokenService:
    """Resolve the TokenService from the DI container."""
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
    return app.resolve(TokenService)  # type: ignore[return-value]


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated user context for the current request."""

    user_id: str
    username: str
    role: Role
    claims: TokenClaims


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    token_service: TokenService = Depends(_get_token_service),
) -> CurrentUser:
    """Extract and validate the JWT Bearer token.

    Returns:
        CurrentUser with the decoded claims.

    Raises:
        HTTPException: 401 if token is missing, invalid, or expired.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = token_service.verify_access_token(credentials.credentials)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid or expired token: {exc}",
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


def require_role(minimum_role: Role):
    """Dependency factory that enforces a minimum role.

    Usage:
        @router.get("/admin/users", dependencies=[Depends(require_role(Role.ADMIN))])
        async def list_users(): ...
    """

    async def _check(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not current_user.role.has_permission(minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"insufficient permissions: {current_user.role.label} "
                    f"requires {minimum_role.label} or higher"
                ),
            )
        return current_user

    return _check


# Pre-built role dependencies for common use.
require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_viewer = require_role(Role.VIEWER)
