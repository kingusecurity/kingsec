"""The concrete exception categories."""

from __future__ import annotations

from kingsec.shared.errors import (
    AuthorizationError,
    ConfigurationError,
    ErrorCode,
    ExternalServiceError,
    KingSecError,
    PersistenceError,
    ResourceNotFoundError,
    ScannerError,
    ServiceTimeoutError,
    ValidationError,
)

ALL_CONCRETE = [
    ConfigurationError,
    ValidationError,
    AuthorizationError,
    ResourceNotFoundError,
    ExternalServiceError,
    ServiceTimeoutError,
    ScannerError,
    PersistenceError,
]


class TestHierarchy:
    def test_all_derive_from_base(self) -> None:
        for cls in ALL_CONCRETE:
            assert issubclass(cls, KingSecError)

    def test_timeout_is_a_kind_of_external_service_error(self) -> None:
        # Callers can catch the broad category and still catch the timeout.
        exc = ServiceTimeoutError("provider slow")
        assert isinstance(exc, ExternalServiceError)
        assert isinstance(exc, KingSecError)


class TestCodes:
    def test_each_category_has_expected_code(self) -> None:
        assert ConfigurationError.code == ErrorCode.CONFIGURATION
        assert AuthorizationError.code == ErrorCode.AUTHORIZATION
        assert ServiceTimeoutError.code == ErrorCode.EXTERNAL_TIMEOUT

    def test_all_codes_are_unique(self) -> None:
        codes = [cls.code for cls in ALL_CONCRETE]
        assert len(codes) == len(set(codes))


class TestSafeMessages:
    def test_every_category_has_a_nonempty_safe_default(self) -> None:
        for cls in ALL_CONCRETE:
            assert cls.default_user_message
            # Safe messages should read as user guidance, not internal jargon.
            assert "Traceback" not in cls.default_user_message

    def test_authorization_message_states_the_requirement(self) -> None:
        # The trust guardrail: the user is told authorization is needed, with no
        # internal reason leaked.
        exc = AuthorizationError("gate check failed for target 10.0.0.5")
        assert "authorized" in exc.user_message.lower()
        assert "10.0.0.5" not in exc.user_message
