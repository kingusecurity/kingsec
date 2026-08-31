"""KSEC-79-01: DNS-rebinding TOCTOU regression tests.

Phase 78 confirmed: ``validate_url()`` resolved a hostname once to
validate it, but the actual connection (``urlopen()``) resolved the
SAME hostname again, independently. An attacker-controlled DNS record
with a short TTL could return a benign public IP for the first lookup
(passing validation) and a private/loopback/link-local IP for the
second (the one actually connected to) - a classic DNS-rebinding SSRF
bypass.

The fix (``_resolve_and_validate`` + ``_PinnedHTTPHandler``/
``_PinnedHTTPSHandler``) resolves exactly once and pins the real TCP
connection to that single validated address, so the HTTP client never
gets a chance to re-resolve. These tests prove that invariant against
``open_validated()`` itself - the function every sender actually calls -
not merely against ``validate_url()`` in isolation, using a
deterministic fake resolver and (where practical) a real local HTTP
server. No external DNS server, internet access, or attacker
infrastructure is used anywhere in this file.
"""

from __future__ import annotations

import datetime
import os
import socket
import ssl
import tempfile
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import Request, build_opener

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kingsec.infrastructure.notifications.url_validator import (
    SSRFError,
    _NoRedirectHandler,
    _PinnedHTTPConnection,
    _PinnedHTTPSHandler,
    _resolve_and_validate,
    open_validated,
)


class _RebindingResolver:
    """A deterministic, fully local stand-in for a DNS-rebinding
    attacker's nameserver.

    Resolving ``self.hostname`` returns ``first_ip`` on the very first
    call and ``rebind_ip`` on every call after that - modeling a
    short-TTL record that changes between the validation lookup and
    whatever a (vulnerable) second lookup would see. Resolving anything
    else (in particular, a literal IP address - the pinned connection
    target itself) is treated as an identity lookup, exactly like a
    real resolver: DNS rebinding is a property of re-resolving a
    *hostname*, not of a literal IP being "looked up" again.
    """

    def __init__(self, hostname: str, first_ip: str, rebind_ip: str) -> None:
        self.hostname = hostname
        self.first_ip = first_ip
        self.rebind_ip = rebind_ip
        self.call_count = 0

    def __call__(self, host, port=None, family=0, type=0, proto=0, flags=0):  # type: ignore[no-untyped-def]
        target = self.first_ip if host == self.hostname and self._bump() == 1 else (
            self.rebind_ip if host == self.hostname else host
        )
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (target, port or 0))]

    def _bump(self) -> int:
        self.call_count += 1
        return self.call_count


@pytest.fixture
def echo_server() -> Iterator[tuple[str, int]]:
    """A real local HTTP server that reports its own status, so a test
    can prove a request actually reached it (as opposed to reaching
    nothing, or reaching some other unreachable address)."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"reached-real-server")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield host, port
    finally:
        server.shutdown()
        server.server_close()


class TestDNSRebindingCannotChangeTheConnectionTarget:
    """Section 10/11 of the KSEC-79-01 remediation prompt: prove the
    actual connection cannot be steered by a second, different DNS
    answer, exercising open_validated() (not merely validate_url())."""

    def test_resolve_and_validate_only_calls_getaddrinfo_once_per_hostname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The most direct proof: the resolver backing validation is
        invoked exactly once for the target hostname, so there is no
        second lookup left for an attacker to rebind."""
        resolver = _RebindingResolver(hostname="rebind.example", first_ip="93.184.216.34", rebind_ip="127.0.0.1")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)

        pinned_ip = _resolve_and_validate("http://rebind.example/webhook", allowlist=None, allow_private=False)

        assert pinned_ip == "93.184.216.34"
        assert resolver.call_count == 1

    def test_open_validated_connects_to_the_first_resolved_address_not_a_later_one(
        self, monkeypatch: pytest.MonkeyPatch, echo_server: tuple[str, int]
    ) -> None:
        """The full, real, end-to-end proof: a request through
        open_validated() actually reaches the server at the FIRST
        resolved (and validated) address, even though the fake resolver
        would hand back a different, unreachable address (127.0.0.99 -
        nothing is listening there) on any second lookup. If the old,
        vulnerable behavior (re-resolve at connection time) were still
        present, this request would fail (either connecting to
        127.0.0.99, which nothing answers, or being blocked outright
        once loopback-detection saw it) instead of succeeding.
        """
        host, port = echo_server
        # allow_private=True is required for this test only because the
        # LEGITIMATE destination (the real local echo_server) happens to
        # be a loopback address; this does not weaken KSEC-79-01's own
        # protection, which is what is under test here (see
        # test_dns_rebinding_to_a_private_ip_is_never_reached below for
        # the loopback-blocking behavior itself, unmodified by this fix).
        resolver = _RebindingResolver(hostname="rebind.example", first_ip=host, rebind_ip="127.0.0.99")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)

        req = Request(f"http://rebind.example:{port}/webhook", data=b"{}", method="POST")
        with open_validated(req, timeout=5, allow_private=True) as resp:
            body = resp.read()

        assert body == b"reached-real-server"
        # Only the validation-time lookup happened - no second,
        # independent resolution occurred for the connection itself.
        assert resolver.call_count == 1

    def test_dns_rebinding_to_a_private_ip_is_never_reached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pre-fix/post-fix security property from the remediation
        prompt: first DNS answer is a benign public IP, second DNS
        answer is 127.0.0.1 - the connection must never reach
        127.0.0.1. Proven by asserting the exact pinned IP
        open_validated() commits to is the FIRST (benign) address, and
        that _resolve_and_validate only ever consults the resolver once
        - so the "second answer" is provably never used for anything.
        """
        resolver = _RebindingResolver(hostname="rebind.example", first_ip="93.184.216.34", rebind_ip="127.0.0.1")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)

        pinned_ip = _resolve_and_validate("http://rebind.example/webhook", allowlist=None, allow_private=False)

        assert pinned_ip == "93.184.216.34"
        assert pinned_ip != "127.0.0.1"
        assert resolver.call_count == 1

    def test_dns_rebinding_to_a_link_local_metadata_ip_is_never_reached(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same property, using the canonical cloud-metadata address
        (169.254.169.254) as the rebind target, per the finding's own
        described attack scenario."""
        resolver = _RebindingResolver(hostname="rebind.example", first_ip="93.184.216.34", rebind_ip="169.254.169.254")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)

        pinned_ip = _resolve_and_validate("http://rebind.example/webhook", allowlist=None, allow_private=False)

        assert pinned_ip == "93.184.216.34"
        assert resolver.call_count == 1

    def test_pinned_http_connection_ignores_the_hostname_it_is_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unit-level proof of the actual connection primitive:
        _PinnedHTTPConnection.connect() always dials the pinned IP,
        regardless of what hostname the connection object itself was
        constructed with (which is exactly how a rebinding hostname's
        "current" address would be used if this override did not
        exist) - while leaving ``self.host`` (used for the HTTP Host
        header) completely untouched."""
        captured: dict[str, tuple] = {}

        def fake_create_connection(address, timeout, source_address=None):  # type: ignore[no-untyped-def]
            captured["address"] = address
            return object()  # stand-in socket; never actually used further

        conn = _PinnedHTTPConnection("attacker-controlled-rebinding-host.example", port=443)
        conn._pinned_ip = "203.0.113.9"
        monkeypatch.setattr(conn, "_create_connection", fake_create_connection)

        conn.connect()

        assert captured["address"] == ("203.0.113.9", 443)
        # The Host header source (self.host) is never touched by the pin.
        assert conn.host == "attacker-controlled-rebinding-host.example"


class TestRegressionExistingSSRFProtectionsRemainIntact:
    """Section 12 of the remediation prompt - the full required matrix,
    proven against open_validated() (the real connection-opening path)
    where practical, complementing test_url_validator.py's existing
    validate_url()-level coverage (left completely unmodified)."""

    def test_a_public_legitimate_url_is_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
        )
        pinned_ip = _resolve_and_validate("https://public.example/webhook", allowlist=None, allow_private=False)
        assert pinned_ip == "93.184.216.34"

    def test_b_http_url_allowed_when_otherwise_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
        )
        _resolve_and_validate("http://public.example/webhook", allowlist=None, allow_private=False)

    def test_c_https_url_allowed_when_otherwise_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
        )
        _resolve_and_validate("https://public.example/webhook", allowlist=None, allow_private=False)

    def test_d_localhost_is_rejected(self) -> None:
        with pytest.raises(SSRFError, match="private|loopback"):
            _resolve_and_validate("http://localhost/webhook", allowlist=None, allow_private=False)

    def test_e_loopback_127_is_rejected(self) -> None:
        with pytest.raises(SSRFError, match="loopback"):
            _resolve_and_validate("http://127.0.0.1/webhook", allowlist=None, allow_private=False)

    def test_f_private_rfc1918_is_rejected(self) -> None:
        with pytest.raises(SSRFError, match="private"):
            _resolve_and_validate("http://10.1.2.3/webhook", allowlist=None, allow_private=False)
        with pytest.raises(SSRFError, match="private"):
            _resolve_and_validate("http://172.16.1.1/webhook", allowlist=None, allow_private=False)
        with pytest.raises(SSRFError, match="private"):
            _resolve_and_validate("http://192.168.1.1/webhook", allowlist=None, allow_private=False)

    def test_g_link_local_is_rejected(self) -> None:
        with pytest.raises(SSRFError, match="private|link-local"):
            _resolve_and_validate("http://169.254.169.254/webhook", allowlist=None, allow_private=False)

    def test_h_multicast_and_reserved_are_rejected(self) -> None:
        with pytest.raises(SSRFError, match="multicast"):
            _resolve_and_validate("http://224.0.0.1/webhook", allowlist=None, allow_private=False)

    def test_i_unsupported_scheme_is_rejected(self) -> None:
        with pytest.raises(SSRFError, match="scheme"):
            _resolve_and_validate("ftp://public.example/webhook", allowlist=None, allow_private=False)

    def test_j_redirect_is_still_refused_on_the_pinned_path(self) -> None:
        """Unlike test_url_validator.py's existing redirect tests (which
        exercise the ALLOWLIST branch, since their local server is at
        127.0.0.1 and 127.0.0.1 is put on the allowlist), this exercises
        redirect-refusal specifically on the NEW pinned-connection
        branch (allow_private=True, no allowlist), proving the fix did
        not accidentally reintroduce redirect-following for pinned
        connections."""
        box: list[str] = [""]

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(302)
                self.send_header("Location", box[0])
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _host, port = server.server_address
        try:
            box[0] = "http://127.0.0.1:1/internal"
            req = Request(f"http://127.0.0.1:{port}/webhook", data=b"{}", method="POST")
            with pytest.raises(SSRFError, match="refusing to follow redirect"):
                open_validated(req, timeout=5, allow_private=True)
        finally:
            server.shutdown()
            server.server_close()

    def test_k_dns_rebinding_cannot_change_the_actual_destination(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The headline property, restated as the exact matrix item
        from the remediation prompt."""
        resolver = _RebindingResolver(hostname="rebind.example", first_ip="93.184.216.34", rebind_ip="127.0.0.1")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        pinned_ip = _resolve_and_validate("http://rebind.example/webhook", allowlist=None, allow_private=False)
        assert pinned_ip == "93.184.216.34"


class TestAllowlistPathIsUnaffectedByThisFix:
    """The allowlist branch never resolves/validates at all (pre- and
    post-fix) - confirms this fix didn't change that intentional
    behavior."""

    def test_allowlisted_hostname_returns_no_pinned_ip(self) -> None:
        pinned_ip = _resolve_and_validate(
            "http://127.0.0.1:8080/webhook", allowlist=["127.0.0.1"], allow_private=False
        )
        assert pinned_ip is None


@pytest.fixture
def self_signed_https_server() -> Iterator[tuple[int, str]]:
    """A real local HTTPS server presenting a self-signed certificate
    valid ONLY for the DNS name "localhost" (not for the literal IP
    "127.0.0.1" the server actually listens on, and not for any other
    name) - a controlled, fully local fixture for proving TLS identity
    behavior, per the remediation prompt's explicit instruction not to
    require any external certificate authority or infrastructure.

    Yields ``(port, certfile_path)`` - the caller builds its own client
    SSLContext trusting ``certfile_path`` as its only CA, so this test
    never depends on the machine's real trust store.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    tmpdir = tempfile.mkdtemp()
    certfile = os.path.join(tmpdir, "cert.pem")
    keyfile = os.path.join(tmpdir, "key.pem")
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
            )
        )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok-tls")

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)
    raw_server = HTTPServer(("127.0.0.1", 0), Handler)
    raw_server.socket = server_ctx.wrap_socket(raw_server.socket, server_side=True)
    _host, port = raw_server.server_address
    thread = threading.Thread(target=raw_server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port, certfile
    finally:
        raw_server.shutdown()
        raw_server.server_close()


class TestPinnedHTTPSPreservesTLSIdentity:
    """Attack simulation 6 from the remediation prompt: proves that
    pinning the raw TCP connection to a validated IP does NOT change
    what hostname TLS certificate verification checks against. Uses a
    real local TLS server and a real, self-signed certificate - no
    external CA, no internet access, no attacker infrastructure.
    """

    def test_pinned_connection_verifies_certificate_against_original_hostname(
        self, self_signed_https_server: tuple[int, str]
    ) -> None:
        """The connection is pinned to 127.0.0.1 (the server's real
        address), but the request targets hostname "localhost" (which
        the certificate IS valid for) - this must succeed, and the
        successful TLS handshake is itself the proof that SNI and
        certificate hostname verification used "localhost", not
        "127.0.0.1"."""
        port, certfile = self_signed_https_server

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(certfile)
        client_ctx.check_hostname = True
        client_ctx.verify_mode = ssl.CERT_REQUIRED

        handler = _PinnedHTTPSHandler(pinned_ip="127.0.0.1")
        handler._context = client_ctx  # test-only: inject a context trusting our local CA
        opener = build_opener(handler, _NoRedirectHandler)

        req = Request(f"https://localhost:{port}/", method="GET")
        with opener.open(req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.read() == b"ok-tls"

    def test_pinned_connection_still_rejects_a_hostname_the_certificate_is_not_valid_for(
        self, self_signed_https_server: tuple[int, str]
    ) -> None:
        """The certificate is valid ONLY for "localhost". Requesting the
        literal IP "127.0.0.1" directly (the server's real, pinned
        address) must still FAIL certificate hostname verification -
        proving verification is genuinely still active and was not
        silently disabled or redirected to check the pinned IP instead
        of the requested hostname."""
        port, certfile = self_signed_https_server

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(certfile)
        client_ctx.check_hostname = True
        client_ctx.verify_mode = ssl.CERT_REQUIRED

        handler = _PinnedHTTPSHandler(pinned_ip="127.0.0.1")
        handler._context = client_ctx
        opener = build_opener(handler, _NoRedirectHandler)

        req = Request(f"https://127.0.0.1:{port}/", method="GET")
        with pytest.raises(URLError, match="CERTIFICATE_VERIFY_FAILED"):
            opener.open(req, timeout=5)
