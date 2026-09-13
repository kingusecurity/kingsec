"""URL target decomposition: UrlComponents, decompose_url(), is_ipv6_literal().

Phase 2B Task 2. Every rejection case is a required test from the Step 1
design's Section 7 and the approved Task 2 Step 2 prompt: explicit port,
default port (80/443), a path, an IPv6 literal, a malformed/scheme-less
URL, a non-numeric port - all reject rather than guess.
"""

from __future__ import annotations

import pytest

from kingsec.domain import (
    InvariantViolation,
    Target,
    TargetDecompositionError,
    TargetType,
    UrlComponents,
    decompose_url,
    is_ipv6_literal,
)


class TestDecomposeUrlAccepts:
    def test_explicit_port(self) -> None:
        components = decompose_url(Target("http://127.0.0.1:18080/", TargetType.URL))
        assert components == UrlComponents(
            scheme="http", host="127.0.0.1", is_ipv6=False, port=18080, port_is_explicit=True, path="/"
        )

    def test_default_port_http(self) -> None:
        components = decompose_url(Target("http://example.com/", TargetType.URL))
        assert components.port == 80
        assert components.port_is_explicit is False

    def test_default_port_https(self) -> None:
        components = decompose_url(Target("https://example.com/", TargetType.URL))
        assert components.port == 443
        assert components.port_is_explicit is False

    def test_path_is_preserved(self) -> None:
        components = decompose_url(Target("http://example.com/admin/panel", TargetType.URL))
        assert components.path == "/admin/panel"

    def test_no_path_is_empty_string(self) -> None:
        components = decompose_url(Target("http://example.com", TargetType.URL))
        assert components.path == ""

    def test_bracketed_ipv6_literal_with_port(self) -> None:
        components = decompose_url(Target("http://[::1]:8080/path", TargetType.URL))
        assert components.host == "::1"
        assert components.is_ipv6 is True
        assert components.port == 8080
        assert components.port_is_explicit is True

    def test_bracketed_ipv6_literal_default_port(self) -> None:
        components = decompose_url(Target("http://[::1]/path", TargetType.URL))
        assert components.host == "::1"
        assert components.is_ipv6 is True
        assert components.port == 80

    def test_ipv4_host_is_not_ipv6(self) -> None:
        components = decompose_url(Target("http://127.0.0.1/", TargetType.URL))
        assert components.is_ipv6 is False


class TestDecomposeUrlRejects:
    def test_non_url_target_type(self) -> None:
        """The one rejection Decision 3 could not move into
        Target._validate_format(): calling decompose_url() on a Target of
        the wrong type is a caller-contract violation the Target itself
        has no way to prevent."""
        with pytest.raises(TargetDecompositionError):
            decompose_url(Target("10.0.0.5", TargetType.IP_ADDRESS))


class TestTargetUrlConstructionRejects:
    """Decision 3 (applied): these used to construct a Target successfully
    and fail later, inside decompose_url() - moved up into
    Target._validate_format() itself, so the bad value is now rejected at
    construction and can never reach decompose_url() (or a scanner) at
    all. See decompose_url()'s docstring for why its own copies of these
    checks are kept anyway, as defense-in-depth, even though they are now
    unreachable for any Target actually reachable in this codebase.
    """

    def test_non_numeric_port(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("http://host:abc/", TargetType.URL)

    def test_port_out_of_range_too_high(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("http://host:99999/", TargetType.URL)

    def test_port_zero_is_rejected(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("http://host:0/", TargetType.URL)

    def test_embedded_credentials(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("http://user:pass@host:80/", TargetType.URL)

    def test_embedded_username_only(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("http://user@host/", TargetType.URL)

    def test_unbracketed_ipv6_shaped_authority(self) -> None:
        # "http://::1:8080/" - urlparse cannot resolve a numeric port from
        # this (RFC 3986 requires brackets for an IPv6 literal authority);
        # this is not special-cased, it falls out of the same port-parsing
        # rejection as a non-numeric port.
        with pytest.raises(InvariantViolation):
            Target("http://::1:8080/path", TargetType.URL)


class TestIsIpv6Literal:
    def test_ipv6_address(self) -> None:
        assert is_ipv6_literal("::1") is True

    def test_ipv4_address(self) -> None:
        assert is_ipv6_literal("127.0.0.1") is False

    def test_hostname_is_not_ipv6(self) -> None:
        assert is_ipv6_literal("example.com") is False

    def test_empty_string_is_not_ipv6(self) -> None:
        assert is_ipv6_literal("") is False
