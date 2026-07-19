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

from kingsec.application.auth import AuthorizationService, Permission
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


# ── Permission-based dependency ─────────────────────────────────────────────


def _get_authz_service(request: Request) -> AuthorizationService:
    """Resolve the ``AuthorizationService`` from the DI container."""
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
    return app.resolve(AuthorizationService)  # type: ignore[return-value]


def require_permission(permission: Permission):
    """Dependency factory that checks for a specific permission.

    Usage::

        @router.delete("/jobs/{job_id}", dependencies=[Depends(require_permission(Permission.LIST_SCANS))])
        async def cancel_job(...): ...
    """

    async def _check(
        current_user: CurrentUser = Depends(get_current_user),
        authz: AuthorizationService = Depends(_get_authz_service),
    ) -> CurrentUser:
        if not authz.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"insufficient permissions: {current_user.role.label} "
                    f"requires '{permission.value}'"
                ),
            )
        return current_user

    return _check


# ── Multi-role dependency ───────────────────────────────────────────────────


def require_any_role(*roles: Role):
    """Dependency factory that allows any of the given roles.

    Usage::

        @router.get("/admin/reports", dependencies=[Depends(require_any_role(Role.ADMIN, Role.ANALYST))])
        async def admin_reports(...): ...
    """

    async def _check(
        current_user: CurrentUser = Depends(get_current_user),
        authz: AuthorizationService = Depends(_get_authz_service),
    ) -> CurrentUser:
        if not authz.has_any_role(current_user.role, *roles):
            role_labels = ", ".join(r.label for r in roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"insufficient permissions: {current_user.role.label} "
                    f"requires one of [{role_labels}]"
                ),
            )
        return current_user

    return _check


# ── Ownership check (admin bypass) ─────────────────────────────────────────


class NotAuthorizedError(Exception):
    """Raised when a user is not authorized for an operation.

    Caught by the web adapter and translated to HTTP 403.
    """


def require_self_or_admin(resource_owner_id: str):
    """Dependency factory that enforces resource ownership.

    Admin users bypass the check.  Non-admin users may only act on
    resources whose ``resource_owner_id`` matches their ``user_id``.

    Usage::

        async def cancel_job(job_id: str, user: CurrentUser = Depends(get_current_user)):
            require_self_or_admin(job_owner_id)(user)
    """

    def _check(current_user: CurrentUser = Depends(get_current_user)) -> None:
        if current_user.role == Role.ADMIN:
            return
        if current_user.user_id != resource_owner_id:
            raise NotAuthorizedError(
                f"user {current_user.user_id} does not own resource "
                f"(owner={resource_owner_id})"
            )

    return _check


# ── Pre-built role dependencies for common use.
require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_viewer = require_role(Role.VIEWER)
