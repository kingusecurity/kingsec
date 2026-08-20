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
import urllib.request
from collections.abc import Iterable
from http.client import HTTPResponse
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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses to follow any HTTP redirect.

    ``validate_url()`` only validates the URL it is given - the *initial*
    request target. ``urllib.request.urlopen()``'s default opener follows
    redirects automatically, which would let a destination that has
    already passed SSRF validation (or is later compromised) redirect the
    connection to an unvalidated internal address, e.g. a cloud metadata
    endpoint at a link-local address. Every outbound call this codebase
    makes to an operator-configured or stored destination URL (SIEM,
    ticketing, webhook, and playbook-webhook integrations) is a one-shot
    POST to a specific API endpoint with no legitimate need to follow a
    redirect, so the safe behavior is to refuse the redirect outright
    rather than silently re-validate and follow it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise SSRFError(f"refusing to follow redirect to {newurl!r} (from {req.full_url!r})")


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def open_validated(
    req: urllib.request.Request,
    *,
    timeout: float,
    allowlist: Iterable[str] | None = None,
) -> HTTPResponse:
    """Validate ``req``'s URL for SSRF, then open it without following redirects.

    The single entry point every outbound HTTP call to an operator-
    configured or stored destination URL should use in this codebase,
    instead of calling ``validate_url()`` and ``urlopen()`` separately -
    that pairing is exactly what a followed redirect can bypass (see
    ``_NoRedirectHandler``).
    """
    validate_url(req.full_url, allowlist=allowlist)
    return _NO_REDIRECT_OPENER.open(req, timeout=timeout)  # type: ignore[no-any-return]


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

    def open(
        self,
        url: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float,
    ) -> None:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            open_validated(req, timeout=timeout, allowlist=self._allowlist)
        except SSRFError as exc:
            raise UnsafeURLError(str(exc)) from exc
