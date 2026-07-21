"""The two hardest guarantees to get right: secret masking and immutability."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kingsec.infrastructure.config import load_settings


class TestSecretMasking:
    """A configured API key must never appear in any string representation."""

    def test_key_absent_from_repr_and_str(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "sk-super-secret-do-not-leak"
        monkeypatch.setenv("KINGSEC_AI__API_KEY", secret)

        settings = load_settings()

        # These are exactly the strings that end up in logs and tracebacks.
        assert secret not in repr(settings)
        assert secret not in str(settings)
        assert secret not in repr(settings.ai)
        assert secret not in str(settings.ai.api_key)

        # ...but the real value is still retrievable on purpose.
        assert settings.ai.api_key.get_secret_value() == secret

    def test_model_dump_keeps_secret_masked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "sk-another-secret"
        monkeypatch.setenv("KINGSEC_AI__API_KEY", secret)

        dumped = repr(load_settings().model_dump())
        assert secret not in dumped


class TestImmutability:
    """The config tree must be frozen after construction (Requirement 7)."""

    def test_cannot_reassign_top_level_group(self) -> None:
        settings = load_settings()
        with pytest.raises(ValidationError):
            settings.server = settings.server  # type: ignore[misc]

    def test_cannot_mutate_nested_field(self) -> None:
        settings = load_settings()
        with pytest.raises(ValidationError):
            settings.server.port = 1234  # type: ignore[misc]
