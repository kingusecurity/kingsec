"""KSEC-85-01 regression tests: SSRF DNS-rebinding/TOCTOU protection at the
real ``AIClient`` HTTP layer.

Phase 84 found that ``AIProviderTester.test_connection()`` and
``AIProviderAdapter._enrich()`` validated a base_url via a check-only
``SSRFURLValidator.validate()`` call and then made a SEPARATE, independent
connection through ``AIClient`` (a plain ``httpx.Client``) - a classic
DNS-rebinding TOCTOU: the address checked is not guaranteed to be the
address connected to. ``AIClient`` now resolves, validates, and pins its
own connection immediately before every request (see ``client.py``'s module
docstring). These tests exercise that real send path - ``post_json()`` -
never ``SSRFURLValidator.validate()``/``_resolve_and_validate()`` in
isolation, which ``tests/unit/infrastructure/test_url_validator_dns_rebinding.py``
(Phase 79) already covers for the underlying primitive.
"""

from __future__ import annotations

import datetime
import os
import socket
import ssl
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kingsec.infrastructure.ai import AIClient
from kingsec.infrastructure.ai.errors import AIError, AIResponseError, AITimeoutError, AIUnsafeURLError
from tests.unit.infrastructure.ai.conftest import transport_from

_OK = httpx.Response(200, json={"ok": True})


def _client(**kwargs: object) -> AIClient:
    kwargs.setdefault("timeout", 5)
    kwargs.setdefault("retry_count", 0)
    kwargs.setdefault("retry_delay", 0)
    return AIClient(**kwargs)  # type: ignore[arg-type]


def _marking_handler(hit: dict) -> Callable[[httpx.Request], httpx.Response]:
    """A MockTransport handler that records that it was reached (and the
    exact host it was reached at) before returning 200 OK - the request
    payload itself is never the point; whether the transport was invoked
    at all is."""

    def handler(request: httpx.Request) -> httpx.Response:
        hit["called"] = True
        hit["host"] = request.url.host
        return _OK

    return handler


class _RebindingResolver:
    """Deterministic, fully local stand-in for a DNS-rebinding attacker's
    nameserver: returns ``first_ip`` on the very first lookup and
    ``rebind_ip`` on every call after that, modelling a short-TTL record
    that changes between the validation lookup and whatever a (vulnerable)
    second lookup would see. Same shape as
    ``test_url_validator_dns_rebinding.py``'s own fixture (Phase 79) - that
    file proves the underlying ``_resolve_and_validate``/``open_validated``
    primitive; this one proves ``AIClient`` (a distinct call site) actually
    uses it correctly, which is exactly the thing KSEC-85-01 found was NOT
    happening.
    """

    def __init__(self, first_ip: str, rebind_ip: str) -> None:
        self.first_ip = first_ip
        self.rebind_ip = rebind_ip
        self.call_count = 0

    def __call__(self, host, port=None, family=0, type=0, proto=0, flags=0):  # type: ignore[no-untyped-def]
        self.call_count += 1
        target = self.first_ip if self.call_count == 1 else self.rebind_ip
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (target, port or 0))]


class TestSSRFBlockingThroughTheRealSendPath:
    """Every case here goes through post_json() - the same method
    AIProviderAdapter/AIProviderTester actually call - not a validator in
    isolation, so a regression that only broke AIClient's own wiring (like
    KSEC-85-01 itself) would be caught."""

    def test_loopback_ip_is_blocked_by_default(self) -> None:
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))
        with pytest.raises(AIUnsafeURLError):
            client.post_json("http://127.0.0.1/v1", {}, {})
        assert hit["called"] is False, "blocked destination was still contacted"

    def test_rfc1918_private_ip_is_blocked_by_default(self) -> None:
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))
        with pytest.raises(AIUnsafeURLError):
            client.post_json("http://10.1.2.3/v1", {}, {})
        assert hit["called"] is False

    def test_link_local_cloud_metadata_ip_is_blocked_even_with_allow_private(self) -> None:
        """169.254.169.254 (AWS/GCP/Azure instance metadata) must stay
        blocked regardless of the local-model-server opt-in flag - it is
        link-local, not loopback/RFC1918, and allow_private never covers it
        (mirrors url_validator.py's own documented policy)."""
        hit = {"called": False}
        client = _client(allow_private=True, transport=transport_from(_marking_handler(hit)))
        with pytest.raises(AIUnsafeURLError):
            client.post_json("http://169.254.169.254/v1", {}, {})
        assert hit["called"] is False

    def test_multicast_ip_is_blocked_even_with_allow_private(self) -> None:
        hit = {"called": False}
        client = _client(allow_private=True, transport=transport_from(_marking_handler(hit)))
        with pytest.raises(AIUnsafeURLError):
            client.post_json("http://224.0.0.1/v1", {}, {})
        assert hit["called"] is False

    def test_hostname_resolving_to_a_private_ip_is_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The base_url itself looks innocuous (a plain hostname); only its
        DNS answer is private. Proves blocking happens post-resolution, at
        the resolved address, not merely a string check on the URL."""
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        )
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))
        with pytest.raises(AIUnsafeURLError):
            client.post_json("http://internal-looking.example/v1", {}, {})
        assert hit["called"] is False

    def test_no_headers_or_payload_are_ever_sent_to_a_blocked_destination(self) -> None:
        """The credential-exfiltration angle: prove nothing - not even the
        connection attempt - reaches the transport, so an API key in
        ``headers`` is never at risk of being sent to a blocked address."""
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))
        with pytest.raises(AIUnsafeURLError):
            client.post_json("http://127.0.0.1/v1", {"Authorization": "Bearer sk-real-secret"}, {"prompt": "x"})
        assert hit == {"called": False}

    def test_loopback_ip_is_allowed_with_allow_private(self) -> None:
        """The permitted case still works - proves the fix does not break
        local-first / local-model-server deployments."""
        hit = {"called": False}
        client = _client(allow_private=True, transport=transport_from(_marking_handler(hit)))
        assert client.post_json("http://127.0.0.1/v1", {}, {}) == {"ok": True}
        assert hit["called"] is True


class TestValidPublicDestinationIsAllowed:
    def test_public_ip_literal_is_reachable(self) -> None:
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))
        assert client.post_json("http://93.184.216.34/v1", {}, {}) == {"ok": True}
        assert hit["called"] is True
        assert hit["host"] == "93.184.216.34"

    def test_hostname_resolving_to_a_public_ip_is_reachable_and_pinned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        )
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))
        assert client.post_json("http://provider.example/v1", {}, {}) == {"ok": True}
        assert hit["called"] is True
        # The connection target is the resolved IP, not the original hostname.
        assert hit["host"] == "93.184.216.34"


class TestDNSRebindingCannotChangeTheConnectionTarget:
    """The headline KSEC-85-01 property: a DNS answer that changes between
    the moment ``AIClient`` resolves it and the moment it would otherwise
    connect must never be able to steer the actual connection."""

    def test_only_one_resolution_happens_and_the_connection_uses_the_first_ip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """allow_private=True here is deliberate: the rebind target
        (10.0.0.9, private) would be blocked anyway if a second, vulnerable
        resolution occurred, which would mask the actual property under
        test (whether a second resolution happens at all) behind an
        exception. With private addresses permitted, a real regression
        shows up unambiguously as ``hit["host"] == "10.0.0.9"``, not as a
        raised error either way.
        """
        resolver = _RebindingResolver(first_ip="93.184.216.34", rebind_ip="10.0.0.9")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        hit = {"called": False}
        client = _client(allow_private=True, transport=transport_from(_marking_handler(hit)))

        result = client.post_json("http://rebind.example/v1", {}, {})

        assert result == {"ok": True}
        assert hit["host"] == "93.184.216.34"
        assert hit["host"] != "10.0.0.9"
        assert resolver.call_count == 1

    def test_rebinding_to_a_private_ip_is_never_reached_when_not_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same rebinding resolver, default (allow_private=False) policy:
        the first (public) answer passes validation and is what gets
        pinned and connected to - the second (private) answer is provably
        never consulted for the connection itself."""
        resolver = _RebindingResolver(first_ip="93.184.216.34", rebind_ip="127.0.0.1")
        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        hit = {"called": False}
        client = _client(transport=transport_from(_marking_handler(hit)))

        result = client.post_json("http://rebind.example/v1", {}, {})

        assert result == {"ok": True}
        assert hit["host"] == "93.184.216.34"
        assert resolver.call_count == 1


@pytest.fixture
def self_signed_https_server() -> Iterator[tuple[int, str]]:
    """A real local HTTPS server presenting a self-signed certificate valid
    ONLY for the DNS name "localhost" (not for the literal IP "127.0.0.1"
    it actually listens on) - a fully local fixture for proving that
    pinning the TCP connection to a raw IP does not change what hostname
    TLS certificate verification checks against. No external CA or
    internet access is used. Same construction as
    ``test_url_validator_dns_rebinding.py``'s own fixture (Phase 79), which
    proves this property for the urllib-based primitive; this one proves
    it for AIClient's independent httpx-based pinning path.
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

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

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


class TestHTTPSCertificateVerificationSurvivesPinning:
    """verify=False must never be used to "solve" SSRF pinning - these
    prove real certificate verification stays active, using a real TLS
    handshake against a real (self-signed, locally-generated) certificate,
    not an assertion about a constructor argument's value."""

    def test_real_verification_succeeds_when_the_hostname_matches_the_certificate(
        self, self_signed_https_server: tuple[int, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """"localhost" is pinned to 127.0.0.1 (the server's real address)
        but the certificate IS valid for "localhost" - success here is
        itself the proof that SNI/hostname verification used "localhost",
        not the pinned IP (a cert valid only for "127.0.0.1" would be a
        weaker, less informative test, since IP SANs are rare in practice;
        this mirrors the actual AI-provider-hostname case)."""
        port, certfile = self_signed_https_server
        # Force a deterministic IPv4 answer for "localhost" only - on a
        # dual-stack host, real getaddrinfo("localhost") can return "::1"
        # first, which url_validator classifies as both loopback AND
        # reserved (Phase 79 behavior, unrelated to this fix) and always
        # rejects; pinning to a concrete, known-good address is the point
        # of this test, not a DNS-stack quirk. Every OTHER lookup (in
        # particular, the underlying socket library's own resolution of
        # the pinned literal IP address when it actually opens the raw
        # TCP connection) must fall through to the real getaddrinfo - it
        # is not a hostname lookup and is not what this test is about.
        real_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
            if host == "localhost":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
            return real_getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        # A CA bundle file path is a valid httpx `verify` value; passed
        # through unchanged by AIClient's verify_ssl parameter.
        client = _client(allow_private=True, verify_ssl=ssl.create_default_context(cafile=certfile))

        result = client.post_json(f"https://localhost:{port}/v1", {}, {})

        assert result == {"ok": True}

    def test_real_verification_still_rejects_a_hostname_the_certificate_is_not_valid_for(
        self, self_signed_https_server: tuple[int, str]
    ) -> None:
        """Requesting the literal pinned IP directly (the certificate is
        valid only for "localhost", not "127.0.0.1") must still fail - if
        this succeeded, it would mean verification was silently checking
        the pinned IP instead of the real hostname, or was disabled."""
        port, certfile = self_signed_https_server
        client = _client(allow_private=True, verify_ssl=ssl.create_default_context(cafile=certfile))

        with pytest.raises(AIError):
            client.post_json(f"https://127.0.0.1:{port}/v1", {}, {})


class TestRedirectCannotBypassPinning:
    """AIClient constructs httpx.Client(follow_redirects=False) and passes
    follow_redirects=False to every .send() explicitly (client.py) - an
    unvalidated redirect target must never be silently followed, which
    would let a validated/pinned destination hand off the real request to
    an entirely different, unvalidated one."""

    @pytest.fixture
    def redirecting_server(self) -> Iterator[tuple[str, int]]:
        """A real local server that always answers with a 302 pointing at
        127.0.0.1:1 - a port nothing listens on. If AIClient ever followed
        this redirect, the request would either hang/timeout or fail with
        a connection-refused error; instead it must be treated as this
        server's own (bodyless) response."""

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/unsafe-target")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            yield host, port
        finally:
            server.shutdown()
            server.server_close()

    def test_redirect_is_not_followed(self, redirecting_server: tuple[str, int]) -> None:
        host, port = redirecting_server
        client = _client(allow_private=True)

        # A followed redirect would try to connect to 127.0.0.1:1 (nothing
        # listens there) and fail as a generic transport AIError; an
        # unfollowed redirect is processed as this server's own empty
        # 302 body, which is not valid JSON - AIResponseError specifically
        # is the signal that the redirect target was never contacted.
        with pytest.raises(AIResponseError):
            client.post_json(f"http://{host}:{port}/v1", {}, {})


class TestTimeoutIsStillEnforced:
    """KSEC-85-01 adds a synchronous DNS resolution before every send; this
    proves the client's own request timeout still fires and is still
    translated to AITimeoutError, i.e. the new step did not change or
    bypass existing timeout handling."""

    @pytest.fixture
    def slow_server(self) -> Iterator[tuple[str, int]]:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                time.sleep(2)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            yield host, port
        finally:
            server.shutdown()
            server.server_close()

    def test_a_slow_destination_still_times_out(self, slow_server: tuple[str, int]) -> None:
        host, port = slow_server
        client = AIClient(timeout=0.2, retry_count=0, retry_delay=0, allow_private=True)

        with pytest.raises(AITimeoutError):
            client.post_json(f"http://{host}:{port}/v1", {}, {})
