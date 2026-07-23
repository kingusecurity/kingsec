"""FastAPI auth dependencies — resolve the current user/API key from tokens.

This module lives entirely inside the web adapter. It never leaks into the
application or domain layers. FastAPI's ``Depends()`` wires the dependency
at request time.

Security considerations:
    - JWT Bearer token is extracted from the ``Authorization`` header.
    - Expired tokens return 401, invalid tokens return 401.
    - Missing/invalid roles return 403.
    - API keys can be provided via ``Authorization: Bearer <key>`` or the
      ``X-API-Key`` header.
    - The dependency is reusable across all protected endpoints.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, cast

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from kingsec.application.auth import AuthorizationService, Permission
from kingsec.application.ports import TokenClaims, TokenService
from kingsec.domain import Role

logger = structlog.get_logger(__name__)

# Security scheme for OpenAPI docs.

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

bearer_scheme = HTTPBearer(auto_error=False)


def _get_token_service(request: Request) -> TokenService:
    """Resolve the TokenService from the DI container."""
    app: Application = request.app.state.kingsec_app
    return cast(TokenService, app.resolve(TokenService))


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
            detail="invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        role = Role[claims.role.upper()]
    except KeyError as exc:
        logger.debug("Invalid role in token", role=claims.role)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token claims",
        ) from exc

    return CurrentUser(
        user_id=claims.user_id,
        username=claims.username,
        role=role,
        claims=claims,
    )


def require_role(minimum_role: Role) -> Callable[..., Any]:
    """Dependency factory that enforces a minimum role.

    Usage:
        @router.get("/admin/users", dependencies=[Depends(require_role(Role.ADMIN))])
        async def list_users(): ...
    """

    async def _check(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not current_user.role.has_permission(minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(f"insufficient permissions: {current_user.role.label} requires {minimum_role.label} or higher"),
            )
        return current_user

    return _check


# ── Permission-based dependency ─────────────────────────────────────────────


def _get_authz_service(request: Request) -> AuthorizationService:
    """Resolve the ``AuthorizationService`` from the DI container."""
    app: Application = request.app.state.kingsec_app
    return cast(AuthorizationService, app.resolve(AuthorizationService))


def require_permission(permission: Permission) -> Callable[..., Any]:
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
                detail=(f"insufficient permissions: {current_user.role.label} requires '{permission.value}'"),
            )
        return current_user

    return _check


# ── Multi-role dependency ───────────────────────────────────────────────────


def require_any_role(*roles: Role) -> Callable[..., Any]:
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
                detail=(f"insufficient permissions: {current_user.role.label} requires one of [{role_labels}]"),
            )
        return current_user

    return _check


# ── Ownership check (admin bypass) ─────────────────────────────────────────


class NotAuthorizedError(Exception):
    """Raised when a user is not authorized for an operation.

    Caught by the web adapter and translated to HTTP 403.
    """


def require_self_or_admin(resource_owner_id: str) -> Callable[..., Any]:
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
            raise NotAuthorizedError(f"user {current_user.user_id} does not own resource (owner={resource_owner_id})")

    return _check


# ── Pre-built role dependencies for common use.
require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_viewer = require_role(Role.VIEWER)

# ── API Key Authentication ────────────────────────────────────────────────────


@dataclass(frozen=True)
class CurrentApiKey:
    """Authenticated API key context for the current request."""

    api_key_id: str
    user_id: str
    scope: str
    status: str


def _get_validate_api_key_use_case(request: Request) -> Any:
    """Resolve the ``ValidateApiKey`` use case from the DI container."""
    app: Application = request.app.state.kingsec_app
    from kingsec.application import ValidateApiKey

    return app.resolve(ValidateApiKey)


async def get_current_api_key(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> CurrentApiKey:
    """Extract and validate an API key from the request.

    Supports two methods:
        1. ``Authorization: Bearer <api_key>``
        2. ``X-API-Key`` header

    Raises:
        HTTPException: 401 if the key is missing, invalid, or revoked.
    """
    api_key_str: str | None = None

    # Try Authorization header first.
    if credentials is not None:
        api_key_str = credentials.credentials

    # Fall back to X-API-Key header.
    if api_key_str is None:
        api_key_str = request.headers.get("X-API-Key")

    if api_key_str is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    validate_uc = _get_validate_api_key_use_case(request)

    from kingsec.application.dto import ValidateApiKeyRequest

    try:
        result = validate_uc.execute(ValidateApiKeyRequest(api_key=api_key_str))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return CurrentApiKey(
        api_key_id=result.api_key_id,
        user_id=result.user_id,
        scope=result.scope,
        status=result.status,
    )
