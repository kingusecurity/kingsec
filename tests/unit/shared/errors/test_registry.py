"""The import-time code registry and duplicate detection."""

from __future__ import annotations

import pytest

from kingsec.shared.errors import (
    AuthorizationError,
    ErrorCode,
    KingSecError,
    ValidationError,
    get_exception_for_code,
    registered_codes,
)


class TestLookup:
    def test_lookup_returns_owning_class(self) -> None:
        assert get_exception_for_code(ErrorCode.AUTHORIZATION) is AuthorizationError
        assert get_exception_for_code(ErrorCode.VALIDATION) is ValidationError

    def test_unknown_code_returns_none(self) -> None:
        assert get_exception_for_code("KS-DOES-NOT-EXIST") is None

    def test_registry_snapshot_is_a_copy(self) -> None:
        snapshot = registered_codes()
        snapshot["KS-FAKE"] = ValidationError  # mutate the copy
        # The real registry must be unaffected.
        assert "KS-FAKE" not in registered_codes()


class TestUniqueness:
    def test_duplicate_code_raises_at_class_creation(self) -> None:
        # Declaring a new class that reuses an existing code must fail loudly,
        # right when the module is imported — not silently at runtime.
        with pytest.raises(ValueError, match="Duplicate KingSec error code"):
            type("DupError", (KingSecError,), {"code": ErrorCode.VALIDATION})

    def test_new_unique_code_registers_cleanly(self) -> None:
        klass = type("BrandNewError", (KingSecError,), {"code": "KS-TEST-999"})
        assert get_exception_for_code("KS-TEST-999") is klass

    def test_subclass_inheriting_parent_code_is_allowed(self) -> None:
        # A subclass that does NOT declare its own code simply inherits the
        # parent's and does not re-register — no false duplicate error.
        klass = type("QuietChild", (ValidationError,), {})
        assert klass.code == ErrorCode.VALIDATION
