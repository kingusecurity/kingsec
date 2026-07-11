"""Tests for User domain entity and Role enum."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from kingsec.domain import Role, User
from kingsec.domain.errors import InvariantViolation
from kingsec.domain.user import (
    InvalidCredentialsError,
    PasswordValidationError,
    UserDisabledError,
    UserError,
    UserNotFoundError,
)


# --- Role enum tests ----------------------------------------------------------


class TestRole:
    def test_role_ordering(self) -> None:
        assert Role.VIEWER < Role.ANALYST < Role.ADMIN

    def test_admin_has_permission_for_analyst(self) -> None:
        assert Role.ADMIN.has_permission(Role.ANALYST)

    def test_analyst_has_permission_for_viewer(self) -> None:
        assert Role.ANALYST.has_permission(Role.VIEWER)

    def test_viewer_does_not_have_permission_for_analyst(self) -> None:
        assert not Role.VIEWER.has_permission(Role.ANALYST)

    def test_viewer_does_not_have_permission_for_admin(self) -> None:
        assert not Role.VIEWER.has_permission(Role.ADMIN)

    def test_role_label(self) -> None:
        assert Role.ADMIN.label == "Admin"
        assert Role.ANALYST.label == "Analyst"
        assert Role.VIEWER.label == "Viewer"

    def test_role_from_value(self) -> None:
        assert Role(10) == Role.VIEWER
        assert Role(20) == Role.ANALYST
        assert Role(30) == Role.ADMIN


# --- User entity tests --------------------------------------------------------


class TestUser:
    def _make_user(self, **kwargs) -> User:
        defaults = dict(
            id="user-001",
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            role=Role.VIEWER,
        )
        defaults.update(kwargs)
        return User(**defaults)

    def test_create_user(self) -> None:
        user = self._make_user()
        assert user.id == "user-001"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == Role.VIEWER
        assert user.is_active is True
        assert user.last_login_at is None

    def test_user_with_admin_role(self) -> None:
        user = self._make_user(role=Role.ADMIN)
        assert user.role == Role.ADMIN

    def test_record_login(self) -> None:
        user = self._make_user()
        assert user.last_login_at is None
        user.record_login()
        assert user.last_login_at is not None
        assert user.last_login_at.tzinfo == timezone.utc

    def test_disable_user(self) -> None:
        user = self._make_user()
        assert user.is_active is True
        user.disable()
        assert user.is_active is False

    def test_enable_user(self) -> None:
        user = self._make_user(is_active=False)
        assert user.is_active is False
        user.enable()
        assert user.is_active is True

    def test_change_role(self) -> None:
        user = self._make_user(role=Role.VIEWER)
        user.change_role(Role.ADMIN)
        assert user.role == Role.ADMIN

    def test_can_with_sufficient_role(self) -> None:
        user = self._make_user(role=Role.ADMIN)
        assert user.can(Role.ANALYST)

    def test_can_with_exact_role(self) -> None:
        user = self._make_user(role=Role.ANALYST)
        assert user.can(Role.ANALYST)

    def test_can_with_insufficient_role(self) -> None:
        user = self._make_user(role=Role.VIEWER)
        assert not user.can(Role.ANALYST)

    def test_can_with_disabled_user(self) -> None:
        user = self._make_user(role=Role.ADMIN, is_active=False)
        assert not user.can(Role.VIEWER)


# --- User validation tests ----------------------------------------------------


class TestUserValidation:
    def _make_user(self, **kwargs) -> User:
        defaults = dict(
            id="user-001",
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            role=Role.VIEWER,
        )
        defaults.update(kwargs)
        return User(**defaults)

    def test_empty_username_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="username must not be empty"):
            self._make_user(username="")

    def test_short_username_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="at least 3 characters"):
            self._make_user(username="ab")

    def test_long_username_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="at most 64 characters"):
            self._make_user(username="a" * 65)

    def test_special_chars_in_username_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="alphanumeric"):
            self._make_user(username="user@name")

    def test_underscore_in_username_ok(self) -> None:
        user = self._make_user(username="user_name")
        assert user.username == "user_name"

    def test_empty_email_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="email must not be empty"):
            self._make_user(email="")

    def test_no_at_in_email_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="email must contain @"):
            self._make_user(email="invalid-email")

    def test_long_email_raises(self) -> None:
        with pytest.raises(InvariantViolation, match="at most 254 characters"):
            self._make_user(email="a" * 245 + "@example.com")


# --- Error classes tests ------------------------------------------------------


class TestUserErrors:
    def test_user_not_found_error(self) -> None:
        exc = UserNotFoundError("user-123")
        assert "user-123" in str(exc)
        assert exc.context["identifier"] == "user-123"

    def test_invalid_credentials_error(self) -> None:
        exc = InvalidCredentialsError()
        assert "invalid username or password" in str(exc)

    def test_user_disabled_error(self) -> None:
        exc = UserDisabledError("testuser")
        assert "testuser" in str(exc)

    def test_password_validation_error(self) -> None:
        exc = PasswordValidationError("too short")
        assert "too short" in str(exc)
