"""URL validation to prevent Server-Side Request Forgery (SSRF).

Every outbound HTTP request made by KingSec must be validated against this
module before the connection is opened.  The validator blocks:

* localhost / loopback addresses (127.0.0.0/8, ::1)
* RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
* Link-local addresses (169.254.0.0/16)
* Multicast ranges (224.0.0.0/4)
* IPv6 unique-local / link-local (fc00::/7, fe80::/10)

A configurable allowlist can override the block for specific hostnames.

KSEC-79-01 (DNS-rebinding TOCTOU): validating a hostname and then letting
the HTTP client re-resolve that same hostname when it actually opens the
connection are two independent DNS lookups. A short-TTL, attacker-
controlled DNS record can return a safe, public address for the first
lookup (satisfying validation) and a private/loopback/link-local address
for the second (the one the connection actually reaches). ``open_validated()``
closes this gap by resolving a hostname exactly ONCE, validating every
address that single resolution returned, and then pinning the real TCP
connection to that validated address - the HTTP client is never given
the chance to resolve the hostname again. The original hostname is still
used for the HTTP ``Host`` header and, for HTTPS, TLS SNI and certificate
hostname verification (see ``_PinnedHTTPSHandler``), so this does not
change what identity a certificate is checked against - only which
socket the bytes are sent to.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.request
from collections.abc import Iterable
from http.client import HTTPResponse
from typing import Any
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


def _reject_if_unsafe(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, raw_ip: str, url: str, *, allow_private: bool
) -> None:
    """Raise ``SSRFError`` if *ip* is not safe to connect to.

    The single source of truth for range-blocking rules, shared by
    ``validate_url()`` and the resolve-and-pin path ``open_validated()``
    uses (via ``_resolve_and_validate()``) - keeping this logic in
    exactly one place is what guarantees the two can never drift apart.
    """
    if ip.is_loopback and not allow_private:
        raise SSRFError(f"URL resolves to loopback address {raw_ip}: {url!r}")
    if ip.is_private and not allow_private:
        raise SSRFError(f"URL resolves to private address {raw_ip}: {url!r}")
    if ip.is_multicast:
        raise SSRFError(f"URL resolves to multicast address {raw_ip}: {url!r}")
    if ip.is_link_local:
        raise SSRFError(f"URL resolves to link-local address {raw_ip}: {url!r}")
    if ip.is_reserved:
        raise SSRFError(f"URL resolves to reserved address {raw_ip}: {url!r}")
    if ip.is_unspecified:
        raise SSRFError(f"URL resolves to unspecified address {raw_ip}: {url!r}")


def _resolve_and_validate(
    url: str, *, allowlist: Iterable[str] | None, allow_private: bool
) -> str | None:
    """Parse, resolve (exactly once), and validate *url*.

    Returns:
        The single validated IP address that the real connection must be
        pinned to, or ``None`` if the hostname is on the allowlist - in
        which case no resolution/validation happens at all (the
        allowlist is itself the trust decision, matching the pre-fix
        behavior) and normal hostname-based connection resolution is
        used.

    Raises:
        SSRFError: no hostname, disallowed scheme, unresolvable
            hostname, or a resolved address in a blocked range - the
            exact same conditions ``validate_url()`` has always
            enforced.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme

    if not hostname:
        raise SSRFError(f"URL has no hostname: {url!r}")

    if scheme not in ("http", "https"):
        raise SSRFError(f"URL scheme {scheme!r} is not allowed (only http/https): {url!r}")

    allowlist_set = frozenset(allowlist or [])
    if hostname in allowlist_set:
        return None

    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError as exc:
        raise SSRFError(f"Cannot resolve hostname {hostname!r}: {exc}") from exc

    # KSEC-79-01: this is the ONLY DNS resolution performed for this
    # call. Every address it returned is validated (unchanged from
    # before this fix); the first validated address becomes the pinned
    # connection target that open_validated() uses - never re-resolved.
    validated: list[str] = []
    for addr in addrinfo:
        raw_ip = str(addr[4][0])
        if raw_ip in validated:
            continue
        ip = ipaddress.ip_address(raw_ip)
        _reject_if_unsafe(ip, raw_ip, url, allow_private=allow_private)
        validated.append(raw_ip)

    return validated[0]


def validate_url(url: str, *, allowlist: Iterable[str] | None = None, allow_private: bool = False) -> None:
    """Validate *url* is safe to open.

    Raises:
        SSRFError: If the URL targets a private/reserved address or cannot
            be resolved.

    Args:
        url: The URL to validate.
        allowlist: Optional iterable of hostnames to allow even if they
            resolve to private addresses.
        allow_private: If True, permit loopback and RFC 1918 private
            addresses (the range a local model server - Ollama, LM Studio,
            an on-prem inference host - would live at). Link-local (e.g.
            169.254.169.254, cloud instance metadata), multicast, and
            reserved addresses are never permitted by this flag - they have
            no legitimate local-server justification and remain blocked
            unconditionally.
    """
    _resolve_and_validate(url, allowlist=allowlist, allow_private=allow_private)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """An ``HTTPConnection`` whose raw TCP connection always dials a
    fixed, pre-validated IP address instead of resolving ``self.host``
    again - the fix for KSEC-79-01's DNS-rebinding TOCTOU. ``self.host``
    is left completely untouched by this override, so the HTTP ``Host``
    header (and, for HTTPS, TLS SNI/certificate hostname verification -
    see ``_PinnedHTTPSConnection``) still use the original hostname.

    ``__init__`` is deliberately NOT overridden: ``HTTPSConnection.
    __init__`` calls its own ``super().__init__(host, port, timeout,
    source_address, blocksize=...)`` with positional arguments that
    would collide with a custom constructor signature once this class
    sits in ``_PinnedHTTPSConnection``'s MRO. ``pinned_ip`` is instead
    set as a plain attribute by the connection factories below,
    immediately after ordinary construction and before ``connect()``
    can ever be called.
    """

    _pinned_ip: str

    def connect(self) -> None:
        # _create_connection and source_address: real runtime attributes
        # set by HTTPConnection.__init__ (confirmed by direct inspection
        # of the installed stdlib), not present in typeshed's stub.
        self.sock = self._create_connection(  # type: ignore[attr-defined]
            (self._pinned_ip, self.port), self.timeout, self.source_address  # type: ignore[attr-defined]
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection, _PinnedHTTPConnection):
    """As ``_PinnedHTTPConnection``, but for HTTPS.

    ``HTTPSConnection.connect()`` is NOT overridden here - its own,
    unmodified implementation calls ``super().connect()`` (which this
    class's MRO resolves to ``_PinnedHTTPConnection.connect()`` above,
    pinning the raw socket) and then wraps that socket with
    ``self._context.wrap_socket(sock, server_hostname=self.host)`` -
    ``self.host`` is the ORIGINAL hostname, so TLS SNI and certificate
    hostname verification are completely unaffected by the pin.
    """


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """Like the default ``HTTPHandler``, but every connection it opens is
    pinned to a pre-resolved, pre-validated IP address (KSEC-79-01)."""

    def __init__(self, pinned_ip: str) -> None:
        super().__init__()
        self._pinned_ip = pinned_ip

    def http_open(self, req: urllib.request.Request) -> HTTPResponse:
        def _connection_factory(host: str, **kwargs: Any) -> _PinnedHTTPConnection:
            conn = _PinnedHTTPConnection(host, **kwargs)
            conn._pinned_ip = self._pinned_ip
            return conn

        return self.do_open(_connection_factory, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Like the default ``HTTPSHandler``, but every connection it opens
    is pinned to a pre-resolved, pre-validated IP address (KSEC-79-01).

    Only the raw TCP socket target changes (see
    ``_PinnedHTTPSConnection``). The default SSL context (full
    certificate + hostname verification) is inherited unchanged from
    ``HTTPSHandler.__init__`` - this class does not construct or weaken
    it in any way.
    """

    def __init__(self, pinned_ip: str) -> None:
        super().__init__()
        self._pinned_ip = pinned_ip

    def https_open(self, req: urllib.request.Request) -> HTTPResponse:
        def _connection_factory(host: str, **kwargs: Any) -> _PinnedHTTPSConnection:
            conn = _PinnedHTTPSConnection(host, **kwargs)
            conn._pinned_ip = self._pinned_ip
            return conn

        # self._context: set by HTTPSHandler.__init__ (a real runtime
        # attribute on every HTTPSHandler instance) but not present in
        # typeshed's stub for the class - the ignore is for that stub
        # gap only, not a workaround for incorrect behavior.
        return self.do_open(_connection_factory, req, context=self._context)  # type: ignore[attr-defined]


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


_NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirectHandler,
)


def _build_opener(pinned_ip: str | None) -> urllib.request.OpenerDirector:
    """An opener that refuses redirects (unchanged from before this fix)
    and, when *pinned_ip* is not ``None``, pins the actual TCP
    connection to that exact validated IP address - closing the
    DNS-rebinding TOCTOU window (KSEC-79-01) between validation and
    connection. ``pinned_ip`` is ``None`` only for allowlisted
    hostnames, which were never resolved/validated in the first place
    (the allowlist itself is the trust decision) - those keep using
    ordinary hostname-based resolution, exactly as before this fix.
    """
    if pinned_ip is None:
        return _NO_REDIRECT_OPENER
    # Do not inherit HTTP(S)_PROXY from the service environment. A proxy
    # replaces the destination host/port after validation, which defeats the
    # guarantee this opener exists to provide and can make the pinned IP use
    # the proxy's port. Integrations that need a proxy require an explicit,
    # separately validated product setting rather than ambient process state.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _PinnedHTTPHandler(pinned_ip),
        _PinnedHTTPSHandler(pinned_ip),
        _NoRedirectHandler,
    )


def open_validated(
    req: urllib.request.Request,
    *,
    timeout: float,
    allowlist: Iterable[str] | None = None,
    allow_private: bool = False,
) -> HTTPResponse:
    """Validate ``req``'s URL for SSRF, then open it without following
    redirects and without re-resolving its hostname (KSEC-79-01).

    The single entry point every outbound HTTP call to an operator-
    configured or stored destination URL should use in this codebase,
    instead of calling ``validate_url()`` and ``urlopen()`` separately -
    that pairing is exactly what a followed redirect (see
    ``_NoRedirectHandler``) or a second, independent DNS resolution (see
    ``_resolve_and_validate``/``_build_opener``) can bypass.
    """
    pinned_ip = _resolve_and_validate(req.full_url, allowlist=allowlist, allow_private=allow_private)
    opener = _build_opener(pinned_ip)
    return opener.open(req, timeout=timeout)  # type: ignore[no-any-return]


class SSRFURLValidator(URLValidationPort):
    """Implements ``URLValidationPort`` using this module's SSRF checks.

    Translates the infrastructure-specific ``SSRFError`` into the port-owned
    ``UnsafeURLError``, so callers in the application layer never need to
    import anything from ``kingsec.infrastructure``.
    """

    def __init__(self, *, allowlist: Iterable[str] | None = None, allow_private: bool = False) -> None:
        self._allowlist = list(allowlist) if allowlist is not None else None
        self._allow_private = allow_private

    def validate(self, url: str) -> None:
        try:
            validate_url(url, allowlist=self._allowlist, allow_private=self._allow_private)
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
            open_validated(req, timeout=timeout, allowlist=self._allowlist, allow_private=self._allow_private)
        except SSRFError as exc:
            raise UnsafeURLError(str(exc)) from exc
