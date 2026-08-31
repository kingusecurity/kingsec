from __future__ import annotations

from dataclasses import dataclass

from kingsec.application.ports import AuditPublisher, PasswordHasher, UserRepository
from kingsec.application.use_cases.change_password import ChangePassword
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.application.use_cases.session_dto import RevokeAllSessionsRequest
from kingsec.domain.audit import AuditAction, AuditEntry


@dataclass(frozen=True)
class DeactivateUserRequest:
    user_id: str
    admin_user_id: str
    admin_username: str = ""


@dataclass(frozen=True)
class ActivateUserRequest:
    user_id: str
    admin_user_id: str
    admin_username: str = ""


@dataclass(frozen=True)
class ResetPasswordRequest:
    user_id: str
    new_password: str
    admin_user_id: str
    admin_username: str = ""


@dataclass(frozen=True)
class AdminUserResponse:
    user_id: str
    username: str
    email: str
    role: str
    is_active: bool


@dataclass(frozen=True)
class SearchUsersRequest:
    query: str | None = None
    role: str | None = None
    is_active: bool | None = None
    limit: int = 50
    offset: int = 0
    order_by: str = "username"
    order_dir: str = "asc"


@dataclass(frozen=True)
class UserListItem:
    user_id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None


@dataclass(frozen=True)
class SearchUsersResponse:
    items: tuple[UserListItem, ...]
    total: int
    limit: int
    offset: int


class DeactivateUser:
    def __init__(self, users: UserRepository, sessions: RevokeAllSessions, audit: AuditPublisher) -> None:
        self._users = users
        self._sessions = sessions
        self._audit = audit

    def execute(self, request: DeactivateUserRequest) -> AdminUserResponse:
        user = self._users.find_by_id(request.user_id)
        if user is None:
            from kingsec.domain.user import UserNotFoundError

            raise UserNotFoundError(request.user_id)
        user.disable()
        self._users.save(user)

        # KSEC-75-02: is_active=False alone doesn't stop an already-issued
        # access token from authenticating (JWT auth trusts the token's
        # own claims, not a fresh DB lookup) - revoke the TARGET user's
        # sessions/tokens immediately, the same RevokeAllSessions
        # mechanism KSEC-73-01/KSEC-75-01 already use, rather than a
        # second, parallel revocation mechanism.
        self._sessions.execute(RevokeAllSessionsRequest(user_id=user.id))

        self._audit.record(
            AuditEntry(
                action=AuditAction.USER_DEACTIVATED,
                resource_type="user",
                resource_id=request.user_id,
                success=True,
                user_id=request.admin_user_id,
                username=request.admin_username,
            )
        )
        return AdminUserResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role.name,
            is_active=user.is_active,
        )


class ActivateUser:
    def __init__(self, users: UserRepository, audit: AuditPublisher) -> None:
        self._users = users
        self._audit = audit

    def execute(self, request: ActivateUserRequest) -> AdminUserResponse:
        user = self._users.find_by_id(request.user_id)
        if user is None:
            from kingsec.domain.user import UserNotFoundError

            raise UserNotFoundError(request.user_id)
        user.enable()
        self._users.save(user)
        self._audit.record(
            AuditEntry(
                action=AuditAction.USER_ACTIVATED,
                resource_type="user",
                resource_id=request.user_id,
                success=True,
                user_id=request.admin_user_id,
                username=request.admin_username,
            )
        )
        return AdminUserResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role.name,
            is_active=user.is_active,
        )


class AdminResetPassword:
    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        sessions: RevokeAllSessions,
        audit: AuditPublisher,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._sessions = sessions
        self._audit = audit

    def execute(self, request: ResetPasswordRequest) -> AdminUserResponse:
        user = self._users.find_by_id(request.user_id)
        if user is None:
            from kingsec.domain.user import UserNotFoundError

            raise UserNotFoundError(request.user_id)
        # Phase 67 / Finding KSEC-64-03: an admin-initiated reset must meet
        # the same complexity policy as every other password-setting path
        # (registration, self-service change) - reuses that canonical
        # validator rather than duplicating its rules here.
        ChangePassword._validate_password(request.new_password)
        user.password_hash = self._hasher.hash(request.new_password)
        self._users.save(user)

        # KSEC-75-01: an admin-initiated password reset is the incident-
        # response tool for a compromised account - it must actually cut
        # the attacker off, not just change a credential the attacker's
        # already-issued tokens never had to prove again. Revokes the
        # TARGET user's sessions/tokens (request.user_id), never the
        # admin's own (request.admin_user_id) - reuses RevokeAllSessions
        # exactly as self-service ChangePassword (KSEC-73-01) does,
        # rather than a second, parallel revocation mechanism.
        self._sessions.execute(RevokeAllSessionsRequest(user_id=user.id))

        self._audit.record(
            AuditEntry(
                action=AuditAction.PASSWORD_RESET,
                resource_type="user",
                resource_id=request.user_id,
                success=True,
                user_id=request.admin_user_id,
                username=request.admin_username,
            )
        )
        return AdminUserResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role.name,
            is_active=user.is_active,
        )


class SearchUsers:
    def __init__(self, users: UserRepository) -> None:
        self._users = users

    def execute(self, request: SearchUsersRequest) -> SearchUsersResponse:
        users, total = self._users.search(
            query=request.query,
            role=request.role,
            is_active=request.is_active,
            limit=request.limit,
            offset=request.offset,
            order_by=request.order_by,
            order_dir=request.order_dir,
        )
        items = tuple(
            UserListItem(
                user_id=u.id,
                username=u.username,
                email=u.email,
                role=u.role.name,
                is_active=u.is_active,
                created_at=u.created_at.isoformat(),
                last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            )
            for u in users
        )
        return SearchUsersResponse(
            items=items,
            total=total,
            limit=request.limit,
            offset=request.offset,
        )
