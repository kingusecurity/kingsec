"""Tests for AI Provider Settings API schemas.

Phase 68 / Finding KSEC-64-04: SaveAIProviderConfigBody and
TestAIProviderConfigBody previously had no max_length on provider,
api_key, model, or base_url. The chosen limits are documented in
ai_provider_routes.py itself: 64 for provider (known identifiers are
short), 512 for api_key (real-world third-party key formats are well
under 200 characters), 128 for model (matches this project's other
short identifier/name fields), 2048 for base_url (matches this
project's existing target/URL field convention).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kingsec.adapters.inbound.web.ai_provider_routes import (
    SaveAIProviderConfigBody,
    TestAIProviderConfigBody,
)


class TestSaveAIProviderConfigBodyProvider:
    def test_below_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="x" * 63).provider) == 63

    def test_exact_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="x" * 64).provider) == 64

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            SaveAIProviderConfigBody(provider="x" * 65)

    def test_real_provider_names_still_accepted(self) -> None:
        for provider in ("openai", "anthropic"):
            assert SaveAIProviderConfigBody(provider=provider).provider == provider


class TestSaveAIProviderConfigBodyApiKey:
    def test_below_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="openai", api_key="x" * 511).api_key) == 511

    def test_exact_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="openai", api_key="x" * 512).api_key) == 512

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            SaveAIProviderConfigBody(provider="openai", api_key="x" * 513)

    def test_omitted_api_key_still_accepted(self) -> None:
        """Existing keep-current-key-when-omitted behavior must remain."""
        assert SaveAIProviderConfigBody(provider="openai").api_key is None


class TestSaveAIProviderConfigBodyModel:
    def test_below_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="openai", model="x" * 127).model) == 127

    def test_exact_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="openai", model="x" * 128).model) == 128

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            SaveAIProviderConfigBody(provider="openai", model="x" * 129)

    def test_real_model_names_still_accepted(self) -> None:
        for model in ("gpt-4o-mini", "claude-sonnet-4-5"):
            assert SaveAIProviderConfigBody(provider="openai", model=model).model == model


class TestSaveAIProviderConfigBodyBaseUrl:
    def test_below_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="openai", base_url="x" * 2047).base_url) == 2047

    def test_exact_limit_accepted(self) -> None:
        assert len(SaveAIProviderConfigBody(provider="openai", base_url="x" * 2048).base_url) == 2048

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            SaveAIProviderConfigBody(provider="openai", base_url="x" * 2049)

    def test_real_base_url_still_accepted(self) -> None:
        url = "https://api.openai.com/v1"
        assert SaveAIProviderConfigBody(provider="openai", base_url=url).base_url == url


class TestTestAIProviderConfigBody:
    """TestAIProviderConfigBody mirrors SaveAIProviderConfigBody's bounds
    exactly (api_key is required here, not optional) - one boundary
    check per field is sufficient given the identical Field()
    definitions; the exhaustive per-field math is already proven above."""

    def test_provider_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            TestAIProviderConfigBody(provider="x" * 65, api_key="k")

    def test_api_key_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            TestAIProviderConfigBody(provider="openai", api_key="x" * 513)

    def test_model_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            TestAIProviderConfigBody(provider="openai", api_key="k", model="x" * 129)

    def test_base_url_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            TestAIProviderConfigBody(provider="openai", api_key="k", base_url="x" * 2049)

    def test_valid_request_still_accepted(self) -> None:
        body = TestAIProviderConfigBody(
            provider="openai",
            api_key="sk-real-key",
            model="gpt-4o-mini",
            base_url="https://api.openai.com/v1",
        )
        assert body.api_key == "sk-real-key"
