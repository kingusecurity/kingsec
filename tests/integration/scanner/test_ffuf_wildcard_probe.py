"""Real-HTTP test of _default_wildcard_probe (Phase 2B-c Priority 1a) -
the actual implementation, not the fake used everywhere else in the unit
suite, against a real local server that either 404s correctly or serves
a catch-all response for every path (mirroring the real Juice Shop
behaviour that motivated this feature - see
docs/E2E-EVIDENCE-PHASE2B.md Defect 3)."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kingsec.infrastructure.scanner.ffuf import _default_wildcard_probe


class _CatchAllHandler(BaseHTTPRequestHandler):
    """Serves HTTP 200 for every path, exactly like Juice Shop's SPA router."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>same page for every path</html>")

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output quiet


class _NormalHandler(BaseHTTPRequestHandler):
    """A real, well-behaved server: 404s for anything that isn't /exists."""

    def do_GET(self) -> None:
        if self.path == "/exists":
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def _run_server(handler: type) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def catch_all_server() -> Iterator[str]:
    yield from _run_server(_CatchAllHandler)


@pytest.fixture
def normal_server() -> Iterator[str]:
    yield from _run_server(_NormalHandler)


class TestRealWildcardProbe:
    def test_catch_all_server_is_detected_as_a_wildcard(self, catch_all_server: str) -> None:
        result = _default_wildcard_probe(f"{catch_all_server}/some-random-nonexistent-path", 5.0)
        assert result is True

    def test_normal_server_returning_404_is_not_a_wildcard(self, normal_server: str) -> None:
        result = _default_wildcard_probe(f"{normal_server}/some-random-nonexistent-path", 5.0)
        assert result is False

    def test_unreachable_target_is_not_treated_as_a_wildcard(self) -> None:
        """A closed port must not be confused with a wildcard condition -
        the real ffuf invocation surfaces connectivity errors properly."""
        result = _default_wildcard_probe("http://127.0.0.1:1/some-path", 2.0)
        assert result is False
