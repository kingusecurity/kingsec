"""Defaults, environment-variable overrides, and .env loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kingsec.infrastructure.config import Environment, LogLevel, load_settings


def _clean_kingsec_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all KINGSEC_* vars so code defaults are actually tested."""
    for key in list(os.environ):
        if key.upper().startswith("KINGSEC_"):
            monkeypatch.delenv(key, raising=False)


class TestDefaults:
    """With no configuration provided, the safe defaults must hold."""

    def test_secure_defaults_are_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_kingsec_env(monkeypatch)
        settings = load_settings()

        # Security guardrails: loopback bind on by default.
        assert settings.server.host == "127.0.0.1"
        assert settings.server.allow_external_bind is False

        # App defaults.
        assert settings.app.environment is Environment.DEVELOPMENT
        assert settings.app.debug is False

        # Logging default the 2.2 module will read.
        assert settings.logging.level is LogLevel.INFO
        assert settings.logging.json_format is False

        # BYO-key: no key required at startup.
        assert settings.ai.api_key is None
        assert settings.server.port == 8765


class TestEnvironmentOverrides:
    """Nested env vars must reach into their groups."""

    def test_nested_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__PORT", "9000")
        monkeypatch.setenv("KINGSEC_LOGGING__LEVEL", "DEBUG")

        settings = load_settings()

        assert settings.server.port == 9000
        assert settings.logging.level is LogLevel.DEBUG

    def test_names_are_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("kingsec_server__port", "7000")
        assert load_settings().server.port == 7000

    def test_api_key_read_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_AI__API_KEY", "sk-secret-value")
        settings = load_settings()

        assert settings.ai.api_key is not None
        # The real value is only reachable through the explicit accessor.
        assert settings.ai.api_key.get_secret_value() == "sk-secret-value"


class TestDotEnvLoading:
    """A .env file must be read, and real env vars must win over it."""

    def test_values_loaded_from_dotenv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_kingsec_env(monkeypatch)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "KINGSEC_SERVER__PORT=5555\nKINGSEC_APP__ENVIRONMENT=testing\n",
            encoding="utf-8",
        )

        settings = load_settings(env_file=env_file)

        assert settings.server.port == 5555
        assert settings.app.environment is Environment.TESTING

    def test_process_env_overrides_dotenv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KINGSEC_SERVER__PORT=5555\n", encoding="utf-8")
        monkeypatch.setenv("KINGSEC_SERVER__PORT", "6666")

        # Precedence: real environment beats the .env file.
        assert load_settings(env_file=env_file).server.port == 6666
