from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request

import pytest

from kingsec.infrastructure.notifications.url_validator import SSRFError, open_validated, validate_url


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

    def test_allows_public_hostname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda hostname, port, family=0, type=0, proto=0, flags=0: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
            ],
        )
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


@pytest.fixture
def redirecting_server() -> Iterator[tuple[str, list]]:
    """A local server that always 302-redirects to a caller-supplied target.

    The target is set on the returned list (index 0) after the fixture
    starts, since the server needs to bind to a port before the test can
    know its own base_url to redirect *to* (Phase 12's redirect tests
    redirect one server's response to another server's address).
    """
    box: list = [""]
    server = ThreadingHTTPServer(("127.0.0.1", 0), _redirect_handler_from_box(box))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", box
    finally:
        server.shutdown()
        server.server_close()


def _redirect_handler_from_box(box: list) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(302)
            self.send_header("Location", box[0])
            self.end_headers()

    return Handler


class TestOpenValidatedRefusesRedirects:
    """Phase 12 §2.1: validate_url() only validates the initial URL - the
    default urlopen() opener follows redirects automatically, which would
    let an already-validated destination redirect the connection to an
    unvalidated internal address after the fact. open_validated() must
    refuse every redirect outright, not silently follow and re-validate it.

    Written to prove open_validated() closes this specific gap, using a
    real local HTTP server (the same pattern as tests/integration/ai/
    conftest.py's ai_server fixture) rather than a mocked urlopen, so the
    real urllib redirect-following machinery is exercised end to end.
    """

    def test_refuses_redirect_to_loopback(self, redirecting_server: tuple[str, list]) -> None:
        base_url, box = redirecting_server
        box[0] = "http://127.0.0.1:1/internal"  # the redirect target
        # Test fixture exercising open_validated()'s own SSRF protection
        # against a real local test server; never opened directly.
        req = Request(base_url, data=b"{}", method="POST")  # noqa: S310
        with pytest.raises(SSRFError, match="refusing to follow redirect"):
            open_validated(req, timeout=5, allowlist=[req.full_url.split("//")[1].split(":")[0]])

    def test_refuses_redirect_even_to_a_public_looking_url(self, redirecting_server: tuple[str, list]) -> None:
        """The refusal is unconditional - it does not matter whether the
        redirect target itself would pass validate_url(); this codebase's
        outbound integration calls have no legitimate reason to follow any
        redirect at all."""
        base_url, box = redirecting_server
        box[0] = "https://example.com/somewhere-else"
        req = Request(base_url, data=b"{}", method="POST")  # noqa: S310
        with pytest.raises(SSRFError, match="refusing to follow redirect"):
            open_validated(req, timeout=5, allowlist=[req.full_url.split("//")[1].split(":")[0]])
