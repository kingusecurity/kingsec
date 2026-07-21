"""Base KingSecError behaviour."""

from __future__ import annotations

import pytest

from kingsec.shared.errors import ErrorCode, KingSecError, ValidationError


class TestMessages:
    def test_internal_and_user_messages_are_separate(self) -> None:
        exc = ValidationError(
            "port 70000 exceeds maximum 65535 in server.port",
            user_message="The provided input is invalid.",
        )
        # Internal detail is preserved for logs...
        assert "70000" in exc.message
        # ...but the user-facing message never carries it.
        assert exc.user_message == "The provided input is invalid."
        assert "70000" not in exc.user_message

    def test_user_message_defaults_to_safe_class_message(self) -> None:
        # A forgotten user_message must fall back to the safe generic, never the
        # internal detail.
        exc = ValidationError("raw internal detail with /etc/secret path")
        assert exc.user_message == ValidationError.default_user_message
        assert "secret" not in exc.user_message


class TestContext:
    def test_context_is_copied_not_referenced(self) -> None:
        original = {"field": "server.port"}
        exc = ValidationError("bad", context=original)
        original["field"] = "mutated"
        # The recorded context must not change when the caller's dict changes.
        assert exc.context == {"field": "server.port"}

    def test_empty_context_by_default(self) -> None:
        assert ValidationError("bad").context == {}


class TestSafeSerialisation:
    def test_to_dict_exposes_only_code_and_user_message(self) -> None:
        exc = ValidationError("internal /var/lib detail", context={"secret_token": "abc"})
        payload = exc.to_dict()
        assert payload == {
            "error_code": ErrorCode.VALIDATION,
            "message": ValidationError.default_user_message,
        }
        # Neither internal message nor context leaks into the API payload.
        assert "internal" not in str(payload)
        assert "secret_token" not in str(payload)

    def test_str_includes_code(self) -> None:
        exc = ValidationError("bad input")
        assert str(exc) == "[KS-VAL-001] bad input"


class TestChaining:
    def test_cause_param_sets_dunder_cause(self) -> None:
        root = ValueError("low-level failure")
        exc = ValidationError("high-level failure", cause=root)
        assert exc.__cause__ is root

    def test_raise_from_preserves_cause(self) -> None:
        root = KeyError("missing")
        try:
            try:
                raise root
            except KeyError as original:
                raise ValidationError("wrapping") from original
        except ValidationError as caught:
            assert caught.__cause__ is root


class TestBaseDefaults:
    def test_base_has_unexpected_code(self) -> None:
        assert KingSecError.code == ErrorCode.UNEXPECTED

    def test_is_an_exception(self) -> None:
        with pytest.raises(KingSecError):
            raise ValidationError("boom")
