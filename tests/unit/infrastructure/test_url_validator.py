from __future__ import annotations

import pytest

from kingsec.infrastructure.notifications.url_validator import SSRFError, validate_url


class TestSSRFValidation:
    def test_rejects_loopback_ipv4(self) -> None:
        with pytest.raises(SSRFError, match="loopback"):
            validate_url("http://127.0.0.1:8080/webhook")

    def test_rejects_loopback_ipv6(self) -> None:
        with pytest.raises(SSRFError, match="loopback"):
            validate_url("http://[::1]:8080/webhook")

    def test_rejects_rfc1918_10(self) -> None:
        with pytest.raises(SSRFError, match="private"):
            validate_url("http://10.0.0.5/webhook")

    def test_rejects_rfc1918_172_16(self) -> None:
        with pytest.raises(SSRFError, match="private"):
            validate_url("http://172.16.0.50/webhook")

    def test_rejects_rfc1918_192_168(self) -> None:
        with pytest.raises(SSRFError, match="private"):
            validate_url("http://192.168.1.1/webhook")

    def test_rejects_link_local(self) -> None:
        with pytest.raises(SSRFError, match="private|link-local"):
            validate_url("http://169.254.1.1/webhook")

    def test_rejects_multicast(self) -> None:
        with pytest.raises(SSRFError, match="multicast"):
            validate_url("http://224.0.0.1/webhook")

    def test_rejects_unspecified(self) -> None:
        with pytest.raises(SSRFError, match="private|unspecified"):
            validate_url("http://0.0.0.0/webhook")

    def test_rejects_empty_hostname(self) -> None:
        with pytest.raises(SSRFError, match="no hostname"):
            validate_url("http:///path")

    def test_allows_public_ip(self) -> None:
        validate_url("http://93.184.216.34")

    def test_allows_public_hostname(self) -> None:
        validate_url("https://hooks.slack.com/services/T00/B00/xxx")

    def test_allows_with_allowlist(self) -> None:
        validate_url("http://127.0.0.1:8080", allowlist=["127.0.0.1"])

    def test_allowlist_skip_resolution(self) -> None:
        validate_url("http://127.0.0.1:8080", allowlist=["127.0.0.1"])

    def test_allowlist_skipped_hostname(self) -> None:
        validate_url("http://hooks.slack.com/services/T00/B00/xxx", allowlist=["hooks.slack.com"])

    def test_rejects_localhost_hostname(self, monkeypatch) -> None:
        with pytest.raises(SSRFError, match="private|loopback"):
            validate_url("http://localhost/webhook")
