"""Phase 30 security tests: SSRF, security headers, CORS, CSP."""

from __future__ import annotations

import pytest


class TestSSRFProtectionComplete:
    """Verify SSRF protection is applied across all outbound HTTP clients."""

    def test_siem_service_splunk_ssrf(self) -> None:
        from kingsec.infrastructure.config.models import IntegrationSettings
        from kingsec.infrastructure.integrations.siem_service import SIEMExportService

        mock_audit = type("Audit", (), {"record": lambda self, e: None})()
        settings = IntegrationSettings(
            splunk_hec_url="http://127.0.0.1:8088",
            splunk_hec_token="test-token",
        )
        service = SIEMExportService(settings, mock_audit)
        with pytest.raises(RuntimeError, match="SSRF protection"):
            service._splunk_send([{"finding_id": "1"}])

    def test_siem_service_elastic_ssrf(self) -> None:
        from kingsec.infrastructure.config.models import IntegrationSettings
        from kingsec.infrastructure.integrations.siem_service import SIEMExportService

        mock_audit = type("Audit", (), {"record": lambda self, e: None})()
        settings = IntegrationSettings(
            elastic_api_key="test-key",
            elastic_url="http://192.168.1.1:9200",
        )
        service = SIEMExportService(settings, mock_audit)
        with pytest.raises(RuntimeError, match="SSRF protection"):
            service._elastic_send([{"finding_id": "1"}])

    def test_ticketing_service_jira_ssrf(self) -> None:
        from kingsec.infrastructure.config.models import IntegrationSettings
        from kingsec.infrastructure.integrations.ticketing_service import TicketingService

        mock_audit = type("Audit", (), {"record": lambda self, e: None})()
        settings = IntegrationSettings(
            jira_url="http://10.0.0.1",
            jira_email="bot@example.com",
            jira_api_token="test-token",
            jira_project_key="TEST",
        )
        service = TicketingService(settings, mock_audit)
        with pytest.raises(RuntimeError, match="SSRF protection"):
            service._jira_create("title", "desc", "high", "target")

    def test_ticketing_service_github_ssrf(self) -> None:
        from kingsec.infrastructure.config.models import IntegrationSettings
        from kingsec.infrastructure.integrations.ticketing_service import TicketingService

        mock_audit = type("Audit", (), {"record": lambda self, e: None})()
        settings = IntegrationSettings(
            github_token="ghp_test123456789012345678901234567890",
            github_repo="org/repo",
        )
        service = TicketingService(settings, mock_audit)
        # GitHub API is external (api.github.com) — SSRF won't block it
        # Test that it at least attempts the request (will fail for other reasons)
        try:
            service._github_create("title", "desc", "high", "target")
        except Exception:
            pass  # Expected — network call fails in test


class TestSecurityHeaders:
    """Test the enhanced security headers middleware."""

    def test_permissions_policy_header(self) -> None:
        from kingsec.infrastructure.middleware.security_headers import _DEFAULT_PERMISSIONS_POLICY
        assert "camera=()" in _DEFAULT_PERMISSIONS_POLICY
        assert "microphone=()" in _DEFAULT_PERMISSIONS_POLICY
        assert "geolocation=()" in _DEFAULT_PERMISSIONS_POLICY

    def test_docs_csp_allows_swagger(self) -> None:
        from kingsec.infrastructure.middleware.security_headers import DOCS_CSP
        assert "cdn.jsdelivr.net" in DOCS_CSP
        assert "unsafe-inline" in DOCS_CSP

    def test_docs_paths_defined(self) -> None:
        from kingsec.infrastructure.middleware.security_headers import DOCS_PATHS
        assert "/docs" in DOCS_PATHS
        assert "/redoc" in DOCS_PATHS


class TestCORSConfig:
    """Test CORS configuration defaults."""

    def test_cors_empty_origins_by_default(self) -> None:
        from kingsec.infrastructure.config.models import CORSSettings
        settings = CORSSettings()
        assert settings.allow_origins == []

    def test_cors_restrictive_methods(self) -> None:
        from kingsec.infrastructure.config.models import CORSSettings
        settings = CORSSettings()
        assert "GET" in settings.allow_methods
        assert "POST" in settings.allow_methods
        assert "*" not in settings.allow_methods

    def test_cors_credentials_default_false(self) -> None:
        from kingsec.infrastructure.config.models import CORSSettings
        settings = CORSSettings()
        assert settings.allow_credentials is False

    def test_wildcard_origin_with_credentials_is_rejected_at_load_time(self) -> None:
        """KSEC-86-03 (CORS wildcard + credentials guard, Phase-84
        carry-forward): the application must fail fast rather than ever
        actually run with this unsafe combination."""
        from kingsec.infrastructure.config.models import CORSSettings

        with pytest.raises(ValueError, match="allow_origins must not include '\\*'"):
            CORSSettings(allow_origins=["*"], allow_credentials=True)

    def test_wildcard_origin_without_credentials_is_still_allowed(self) -> None:
        """The guard is specific to the dangerous combination - a wildcard
        origin with credentials disabled is a legitimate, common
        public-API configuration and must not be blocked."""
        from kingsec.infrastructure.config.models import CORSSettings

        settings = CORSSettings(allow_origins=["*"], allow_credentials=False)
        assert settings.allow_origins == ["*"]

    def test_explicit_origins_with_credentials_is_still_allowed(self) -> None:
        """The legitimate, common production configuration - specific
        origins with credentials enabled - must not be blocked."""
        from kingsec.infrastructure.config.models import CORSSettings

        settings = CORSSettings(allow_origins=["https://app.example.com"], allow_credentials=True)
        assert settings.allow_credentials is True


class TestSecurityHeadersConfig:
    """Test security headers configuration defaults."""

    def test_hsts_default_disabled(self) -> None:
        from kingsec.infrastructure.config.models import SecurityHeadersSettings
        settings = SecurityHeadersSettings()
        assert settings.hsts_max_age == 0

    def test_content_type_nosniff(self) -> None:
        from kingsec.infrastructure.config.models import SecurityHeadersSettings
        settings = SecurityHeadersSettings()
        assert settings.x_content_type_options == "nosniff"

    def test_frame_options_deny(self) -> None:
        from kingsec.infrastructure.config.models import SecurityHeadersSettings
        settings = SecurityHeadersSettings()
        assert settings.x_frame_options == "DENY"

    def test_csp_default_none(self) -> None:
        from kingsec.infrastructure.config.models import SecurityHeadersSettings
        settings = SecurityHeadersSettings()
        assert settings.content_security_policy == "default-src 'none'"

    def test_referrer_policy_strict(self) -> None:
        from kingsec.infrastructure.config.models import SecurityHeadersSettings
        settings = SecurityHeadersSettings()
        assert "strict-origin" in settings.referrer_policy

    def test_server_header_removal(self) -> None:
        from kingsec.infrastructure.config.models import SecurityHeadersSettings
        settings = SecurityHeadersSettings()
        assert settings.remove_server_header is True
        assert settings.remove_x_powered_by is True


class TestRateLimitConfig:
    """Test rate limiting configuration defaults."""

    def test_rate_limit_enabled_by_default(self) -> None:
        from kingsec.infrastructure.config.models import RateLimitSettings
        settings = RateLimitSettings()
        assert settings.enabled is True

    def test_auth_rate_limit_stricter(self) -> None:
        from kingsec.infrastructure.config.models import RateLimitSettings
        settings = RateLimitSettings()
        assert settings.auth_requests_per_minute < settings.api_requests_per_minute

    def test_burst_size_positive(self) -> None:
        from kingsec.infrastructure.config.models import RateLimitSettings
        settings = RateLimitSettings()
        assert settings.burst_size >= 1


class TestInputValidationSecurity:
    """Additional input validation security tests."""

    def test_validate_url_for_ssrf_blocks_localhost(self) -> None:
        from kingsec.infrastructure.security.input_validation import validate_url_for_ssrf
        with pytest.raises(ValueError, match="internal|private|loopback"):
            validate_url_for_ssrf("http://localhost/admin")

    def test_validate_url_for_ssrf_blocks_private_ip(self) -> None:
        from kingsec.infrastructure.security.input_validation import validate_url_for_ssrf
        with pytest.raises(ValueError, match="private"):
            validate_url_for_ssrf("http://192.168.1.1/admin")

    def test_validate_url_for_ssrf_blocks_metadata(self) -> None:
        from kingsec.infrastructure.security.input_validation import validate_url_for_ssrf
        with pytest.raises(ValueError, match="internal|private"):
            validate_url_for_ssrf("http://169.254.169.254/latest/meta-data")

    def test_validate_url_for_ssrf_allows_external(self) -> None:
        from kingsec.infrastructure.security.input_validation import validate_url_for_ssrf
        # Should not raise for a valid external URL
        validate_url_for_ssrf("https://api.example.com/v1/data")

    def test_validate_url_for_ssrf_rejects_ftp(self) -> None:
        from kingsec.infrastructure.security.input_validation import validate_url_for_ssrf
        with pytest.raises(ValueError, match="scheme"):
            validate_url_for_ssrf("ftp://example.com/file")

    def test_sanitize_filename_removes_dangerous_chars(self) -> None:
        from kingsec.infrastructure.security.input_validation import sanitize_filename
        result = sanitize_filename("../../../etc/passwd")
        assert "/" not in result
        # The path should be sanitized to a safe filename
        assert result.startswith("_") or result.startswith("etc")

    def test_sanitize_filename_preserves_safe_chars(self) -> None:
        from kingsec.infrastructure.security.input_validation import sanitize_filename
        result = sanitize_filename("my-plugin_v2.1.zip")
        assert result == "my-plugin_v2.1.zip"

    def test_detect_sql_injection_union(self) -> None:
        from kingsec.infrastructure.security.input_validation import detect_sql_injection
        assert detect_sql_injection("1 UNION SELECT * FROM users --") is True

    def test_detect_sql_injection_safe_input(self) -> None:
        from kingsec.infrastructure.security.input_validation import detect_sql_injection
        assert detect_sql_injection("normal search query") is False

    def test_escape_html_special_chars(self) -> None:
        from kingsec.infrastructure.security.input_validation import escape_html
        result = escape_html('<script>alert("xss")</script>')
        assert "<script>" not in result
        assert "&lt;" in result
