"""Fail-fast validation and the security guardrails."""

from __future__ import annotations

import os

import pytest

from kingsec.infrastructure.config import ConfigError, load_settings
from kingsec.infrastructure.config.models import ReportingSettings


class TestFailFast:
    """Invalid values must raise a clear ConfigError, not start the app."""

    def test_out_of_range_port_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__PORT", "99999")

        with pytest.raises(ConfigError) as excinfo:
            load_settings()

        message = str(excinfo.value)
        # The message must point at the exact knob to turn.
        assert "server.port" in message
        assert "KINGSEC_SERVER__PORT" in message

    def test_invalid_log_level_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_LOGGING__LEVEL", "VERBOSE")
        with pytest.raises(ConfigError):
            load_settings()

    def test_invalid_base_url_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_AI__BASE_URL", "ftp://example.com")
        with pytest.raises(ConfigError) as excinfo:
            load_settings()
        assert "base_url" in str(excinfo.value)

    def test_unknown_nested_key_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A typo in one of KingSec's own keys must fail, not be silently ignored.
        monkeypatch.setenv("KINGSEC_SERVER__PROT", "8000")
        with pytest.raises(ConfigError):
            load_settings()


class TestLoopbackGuardrail:
    """Binding to all interfaces requires an explicit opt-in."""

    def test_wildcard_bind_rejected_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__HOST", "0.0.0.0")
        with pytest.raises(ConfigError) as excinfo:
            load_settings()
        assert "all network interfaces" in str(excinfo.value)

    def test_wildcard_bind_allowed_with_explicit_optin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__HOST", "0.0.0.0")
        monkeypatch.setenv("KINGSEC_SERVER__ALLOW_EXTERNAL_BIND", "true")

        settings = load_settings()
        assert settings.server.host == "0.0.0.0"
        assert settings.server.allow_external_bind is True


class TestEnvironmentConsistency:
    """Cross-field rules run at startup."""

    def test_debug_in_production_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_APP__ENVIRONMENT", "production")
        monkeypatch.setenv("KINGSEC_APP__DEBUG", "true")
        with pytest.raises(ConfigError) as excinfo:
            load_settings()
        assert "production" in str(excinfo.value)


class TestReportFormatSettings:
    """KINGSEC_REPORTING__REPORT_FORMAT parsing and the OS-aware default.

    HTML needs no native libraries, so Windows (where pip cannot provide
    WeasyPrint's GTK3 runtime) defaults to it; PDF everywhere else. An
    explicit value always wins over the OS default.
    """

    def test_html_format_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_REPORTING__REPORT_FORMAT", "html")
        assert load_settings().reporting.report_format == "html"

    def test_pdf_format_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_REPORTING__REPORT_FORMAT", "pdf")
        assert load_settings().reporting.report_format == "pdf"

    def test_format_value_is_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_REPORTING__REPORT_FORMAT", "HTML")
        assert load_settings().reporting.report_format == "html"

    def test_invalid_format_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KINGSEC_REPORTING__REPORT_FORMAT", "docx")
        with pytest.raises(ConfigError):
            load_settings()

    def test_default_is_pdf_on_posix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KINGSEC_REPORTING__REPORT_FORMAT", raising=False)
        monkeypatch.setattr(os, "name", "posix")
        assert load_settings().reporting.report_format == "pdf"

    def test_default_is_html_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # NOTE: ReportingSettings is constructed directly, not via
        # load_settings(), because patching os.name to "nt" on Linux makes
        # pathlib resolve WindowsPath — which cannot be instantiated here —
        # and full Settings construction evaluates StorageSettings'
        # Path.home() default. The unit under test is the default_factory.
        monkeypatch.setattr(os, "name", "nt")
        assert ReportingSettings().report_format == "html"

    def test_explicit_pdf_wins_over_windows_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "name", "nt")
        assert ReportingSettings(report_format="pdf").report_format == "pdf"
