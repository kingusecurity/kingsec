"""URL validation to prevent Server-Side Request Forgery (SSRF).

Every outbound HTTP request made by KingSec must be validated against this
module before the connection is opened.  The validator blocks:

* localhost / loopback addresses (127.0.0.0/8, ::1)
* RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
* Link-local addresses (169.254.0.0/16)
* Multicast ranges (224.0.0.0/4)
* IPv6 unique-local / link-local (fc00::/7, fe80::/10)

A configurable allowlist can override the block for specific hostnames.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlparse

from kingsec.application.ports import UnsafeURLError, URLValidationPort

# ---------------------------------------------------------------------------
# Private / dangerous IP ranges
# ---------------------------------------------------------------------------

_PRIVATE_NETS: list[str] = [
    "127.0.0.0/8",  # loopback
    "10.0.0.0/8",  # RFC 1918
    "172.16.0.0/12",  # RFC 1918
    "192.168.0.0/16",  # RFC 1918
    "169.254.0.0/16",  # link-local
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved (RFC 1112)
    "0.0.0.0/8",  # "this" network
    "::1/128",  # IPv6 loopback
    "fc00::/7",  # IPv6 unique-local
    "fe80::/10",  # IPv6 link-local
    "ff00::/8",  # IPv6 multicast
]


class SSRFError(ValueError):
    """Raised when a URL is blocked by SSRF validation."""


def validate_url(url: str, *, allowlist: Iterable[str] | None = None) -> None:
    """Validate *url* is safe to open.

    Raises:
        SSRFError: If the URL targets a private/reserved address or cannot
            be resolved.

    Args:
        url: The URL to validate.
        allowlist: Optional iterable of hostnames to allow even if they
            resolve to private addresses.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme

    if not hostname:
        raise SSRFError(f"URL has no hostname: {url!r}")

    if scheme not in ("http", "https"):
        raise SSRFError(f"URL scheme {scheme!r} is not allowed (only http/https): {url!r}")

    allowlist_set = frozenset(allowlist or [])

    # Bypass resolution for allowlisted hostnames.
    if hostname in allowlist_set:
        return

    # Resolve the hostname to IP addresses.
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError as exc:
        raise SSRFError(f"Cannot resolve hostname {hostname!r}: {exc}") from exc

    addresses = {addr[4][0] for addr in addrinfo}

    for raw_ip in addresses:
        ip = ipaddress.ip_address(raw_ip)

        # Check allowlist first.
        if hostname in allowlist_set:
            continue

        if ip.is_loopback:
            raise SSRFError(f"URL resolves to loopback address {raw_ip}: {url!r}")
        if ip.is_private:
            raise SSRFError(f"URL resolves to private address {raw_ip}: {url!r}")
        if ip.is_multicast:
            raise SSRFError(f"URL resolves to multicast address {raw_ip}: {url!r}")
        if ip.is_link_local:
            raise SSRFError(f"URL resolves to link-local address {raw_ip}: {url!r}")
        if ip.is_reserved:
            raise SSRFError(f"URL resolves to reserved address {raw_ip}: {url!r}")
        if ip.is_unspecified:
            raise SSRFError(f"URL resolves to unspecified address {raw_ip}: {url!r}")


class SSRFURLValidator(URLValidationPort):
    """Implements ``URLValidationPort`` using this module's SSRF checks.

    Translates the infrastructure-specific ``SSRFError`` into the port-owned
    ``UnsafeURLError``, so callers in the application layer never need to
    import anything from ``kingsec.infrastructure``.
    """

    def __init__(self, *, allowlist: Iterable[str] | None = None) -> None:
        self._allowlist = list(allowlist) if allowlist is not None else None

    def validate(self, url: str) -> None:
        try:
            validate_url(url, allowlist=self._allowlist)
        except SSRFError as exc:
            raise UnsafeURLError(str(exc)) from exc
