"""Fail-fast validation and the security guardrails."""

from __future__ import annotations

import pytest

from kingsec.infrastructure.config import ConfigError, load_settings


class TestFailFast:
    """Invalid values must raise a clear ConfigError, not start the app."""

    def test_out_of_range_port_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__PORT", "99999")

        with pytest.raises(ConfigError) as excinfo:
            load_settings()

        message = str(excinfo.value)
        # The message must point at the exact knob to turn.
        assert "server.port" in message
        assert "KINGSEC_SERVER__PORT" in message

    def test_invalid_log_level_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KINGSEC_LOGGING__LEVEL", "VERBOSE")
        with pytest.raises(ConfigError):
            load_settings()

    def test_invalid_base_url_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KINGSEC_AI__BASE_URL", "ftp://example.com")
        with pytest.raises(ConfigError) as excinfo:
            load_settings()
        assert "base_url" in str(excinfo.value)

    def test_unknown_nested_key_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A typo in one of KingSec's own keys must fail, not be silently ignored.
        monkeypatch.setenv("KINGSEC_SERVER__PROT", "8000")
        with pytest.raises(ConfigError):
            load_settings()


class TestLoopbackGuardrail:
    """Binding to all interfaces requires an explicit opt-in."""

    def test_wildcard_bind_rejected_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__HOST", "0.0.0.0")
        with pytest.raises(ConfigError) as excinfo:
            load_settings()
        assert "all network interfaces" in str(excinfo.value)

    def test_wildcard_bind_allowed_with_explicit_optin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__HOST", "0.0.0.0")
        monkeypatch.setenv("KINGSEC_SERVER__ALLOW_EXTERNAL_BIND", "true")

        settings = load_settings()
        assert settings.server.host == "0.0.0.0"
        assert settings.server.allow_external_bind is True


class TestEnvironmentConsistency:
    """Cross-field rules run at startup."""

    def test_debug_in_production_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KINGSEC_APP__ENVIRONMENT", "production")
        monkeypatch.setenv("KINGSEC_APP__DEBUG", "true")
        with pytest.raises(ConfigError) as excinfo:
            load_settings()
        assert "production" in str(excinfo.value)
