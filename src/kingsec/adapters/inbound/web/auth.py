"""FastAPI auth dependencies — resolve the current user/API key from tokens.

This module lives entirely inside the web adapter. It never leaks into the
application or domain layers. FastAPI's ``Depends()`` wires the dependency
at request time.

Security considerations:
    - JWT Bearer token is extracted from the ``Authorization`` header.
    - Expired tokens return 401, invalid tokens return 401.
    - Missing/invalid roles return 403.
    - API keys can be provided via ``Authorization: Bearer <key>`` or the
      ``X-API-Key`` header. ``get_current_user()`` accepts both: a bearer
      credential starting with ``ks_`` (the API key format), or no bearer
      credential at all but an ``X-API-Key`` header, is treated as an API
      key; anything else is treated as a JWT. This is a deliberate dispatch
      on the token's own shape, not "try JWT, catch, try key" — a malformed
      JWT should stay a JWT error, not get reinterpreted as a (also
      invalid) key attempt.
    - An API-key-authenticated request additionally requires the key's
      owning account to still be active, and (for ``read_only``-scoped
      keys) restricts the request to safe HTTP methods (GET/HEAD/OPTIONS).
    - Session management, MFA setup/management, password change, API key
      management, and user/role administration deliberately stay
      JWT-only — see ``get_current_user_jwt_only()`` and the ``jwt_only``
      parameter on ``require_role``/``require_permission``/
      ``require_any_role``. Fresh interactive login is itself a security
      property on those routes, not just an implementation detail.
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
from kingsec.application.ports import TokenClaims, TokenService, UserRepository
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


def _get_user_repository(request: Request) -> UserRepository:
    """Resolve the UserRepository from the DI container."""
    app: Application = request.app.state.kingsec_app
    return cast(UserRepository, app.resolve(UserRepository))


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated user context for the current request.

    ``claims`` and ``api_key`` are mutually exclusive: a JWT-authenticated
    request sets ``claims`` and leaves ``api_key`` as ``None``; an
    API-key-authenticated request sets ``api_key`` and leaves ``claims`` as
    ``None`` (there is no real JWT behind an API key, so there is nothing
    honest to put there). Code that specifically needs a live access
    token's claims (e.g. its ``jti``, to look up the session tied to
    *this* token) must run on a route using ``get_current_user_jwt_only()``,
    where ``claims`` is always present.
    """

    user_id: str
    username: str
    role: Role
    claims: TokenClaims | None = None
    api_key: CurrentApiKey | None = None


def _verify_jwt(credentials: HTTPAuthorizationCredentials, token_service: TokenService) -> CurrentUser:
    """Extract and validate a JWT Bearer token. Shared by both `get_current_user()` variants."""
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


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _authenticate_api_key(request: Request, api_key_str: str) -> CurrentUser:
    """Validate an API key and resolve it to a CurrentUser.

    Two checks beyond plain key validity, both required for this to be
    safe to use broadly (neither existed when the key mechanism was only
    reachable from ``/apikeys/me``, where they didn't matter):
        - The key's owning account must still exist and be active. A
          deactivated user's key must stop working, not keep going.
        - A ``read_only``-scoped key may only be used for safe HTTP
          methods (GET/HEAD/OPTIONS). ``full_access`` has no extra
          restriction here - it's still bounded by the owner's own role,
          checked separately by whatever role/permission guard the route
          itself uses.
    """
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

    user_repo = _get_user_repository(request)
    owner = user_repo.find_by_id(result.user_id)
    if owner is None or not owner.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if result.scope == "read_only" and request.method not in _SAFE_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this API key is read-only",
        )

    return CurrentUser(
        user_id=owner.id,
        username=owner.username,
        role=owner.role,
        api_key=CurrentApiKey(
            api_key_id=result.api_key_id,
            user_id=result.user_id,
            scope=result.scope,
            status=result.status,
        ),
    )


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    token_service: TokenService = Depends(_get_token_service),
) -> CurrentUser:
    """Resolve the current caller from either a JWT or an API key.

    Dispatch is on the credential's own shape, not on catching a JWT
    failure and retrying as a key: a bearer credential starting with
    ``ks_`` (the API key format), or no bearer credential at all but an
    ``X-API-Key`` header present, is treated as an API key. Anything else
    goes through the same JWT verification this dependency has always
    done.

    Returns:
        CurrentUser - JWT-derived (``claims`` set) or API-key-derived
        (``api_key`` set).

    Raises:
        HTTPException: 401 if there's no usable credential, or it's
            invalid/expired/revoked; 403 if a read_only key is used on a
            mutating request.
    """
    if credentials is not None and not credentials.credentials.startswith("ks_"):
        return _verify_jwt(credentials, token_service)

    api_key_str = credentials.credentials if credentials is not None else request.headers.get("X-API-Key")

    if api_key_str is not None:
        return _authenticate_api_key(request, api_key_str)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_jwt_only(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    token_service: TokenService = Depends(_get_token_service),
) -> CurrentUser:
    """Today's exact original `get_current_user()` behavior: JWT only, no API-key fallback.

    Used on routes where a fresh interactive login is itself a security
    property, not just an implementation detail: session management, MFA
    setup/management, password change, API key management, and user/role
    administration. An API key must never be able to touch any of these,
    regardless of its scope.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _verify_jwt(credentials, token_service)


def require_role(minimum_role: Role, *, jwt_only: bool = False) -> Callable[..., Any]:
    """Dependency factory that enforces a minimum role.

    Usage:
        @router.get("/admin/users", dependencies=[Depends(require_role(Role.ADMIN))])
        async def list_users(): ...

    Pass ``jwt_only=True`` on routes where API-key auth must never apply
    regardless of the caller's role (see `get_current_user_jwt_only()`).
    """
    current_user_dep = get_current_user_jwt_only if jwt_only else get_current_user

    async def _check(current_user: CurrentUser = Depends(current_user_dep)) -> CurrentUser:
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


def require_permission(permission: Permission, *, jwt_only: bool = False) -> Callable[..., Any]:
    """Dependency factory that checks for a specific permission.

    Usage::

        @router.delete("/jobs/{job_id}", dependencies=[Depends(require_permission(Permission.LIST_SCANS))])
        async def cancel_job(...): ...

    Pass ``jwt_only=True`` on routes where API-key auth must never apply
    (see `get_current_user_jwt_only()`) - used for API key management
    itself (create/list/rotate/revoke), so a leaked key can't mint or
    revoke keys.
    """
    current_user_dep = get_current_user_jwt_only if jwt_only else get_current_user

    async def _check(
        current_user: CurrentUser = Depends(current_user_dep),
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


def require_any_role(*roles: Role, jwt_only: bool = False) -> Callable[..., Any]:
    """Dependency factory that allows any of the given roles.

    Usage::

        @router.get("/admin/reports", dependencies=[Depends(require_any_role(Role.ADMIN, Role.ANALYST))])
        async def admin_reports(...): ...

    Pass ``jwt_only=True`` on routes where API-key auth must never apply
    (see `get_current_user_jwt_only()`).
    """
    current_user_dep = get_current_user_jwt_only if jwt_only else get_current_user

    async def _check(
        current_user: CurrentUser = Depends(current_user_dep),
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

# ── Pre-built role dependencies for routes API keys must never reach
# (session management, MFA setup/management, password change, user/role
# administration) - see `get_current_user_jwt_only()`.
require_admin_jwt_only = require_role(Role.ADMIN, jwt_only=True)
require_analyst_jwt_only = require_role(Role.ANALYST, jwt_only=True)
require_viewer_jwt_only = require_role(Role.VIEWER, jwt_only=True)

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
