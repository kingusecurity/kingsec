from __future__ import annotations

from dataclasses import dataclass

from kingsec.application.ports import AuditPublisher, PasswordHasher, UserRepository
from kingsec.domain.audit import AuditAction, AuditEntry


@dataclass(frozen=True)
class DeactivateUserRequest:
    user_id: str
    admin_user_id: str


@dataclass(frozen=True)
class ActivateUserRequest:
    user_id: str
    admin_user_id: str


@dataclass(frozen=True)
class ResetPasswordRequest:
    user_id: str
    new_password: str
    admin_user_id: str


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
    def __init__(self, users: UserRepository, audit: AuditPublisher) -> None:
        self._users = users
        self._audit = audit

    def execute(self, request: DeactivateUserRequest) -> AdminUserResponse:
        user = self._users.find_by_id(request.user_id)
        if user is None:
            from kingsec.domain.user import UserNotFoundError

            raise UserNotFoundError(request.user_id)
        user.disable()
        self._users.save(user)
        self._audit.record(
            AuditEntry(
                action=AuditAction.USER_DEACTIVATED,
                resource_type="user",
                resource_id=request.user_id,
                success=True,
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
    def __init__(self, users: UserRepository, hasher: PasswordHasher, audit: AuditPublisher) -> None:
        self._users = users
        self._hasher = hasher
        self._audit = audit

    def execute(self, request: ResetPasswordRequest) -> AdminUserResponse:
        user = self._users.find_by_id(request.user_id)
        if user is None:
            from kingsec.domain.user import UserNotFoundError

            raise UserNotFoundError(request.user_id)
        user.password_hash = self._hasher.hash(request.new_password)
        self._users.save(user)
        self._audit.record(
            AuditEntry(
                action=AuditAction.PASSWORD_RESET,
                resource_type="user",
                resource_id=request.user_id,
                success=True,
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
