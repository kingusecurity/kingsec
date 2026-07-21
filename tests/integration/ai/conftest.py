"""Fixtures for AI integration tests — a real local HTTP server.

Unlike the unit tests (which use httpx.MockTransport), these run against an
actual socket server so the real network path, connection pooling, and error
handling are exercised end to end.
"""

from __future__ import annotations

import io
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging

_ENRICHMENT = {
    "title": "Fix SQL Injection",
    "explanation": "Injectable parameter.",
    "business_impact": "Data exfiltration.",
    "remediation": "Use parameterised queries.",
    "references": ["https://owasp.org/sqli"],
    "confidence": 0.88,
}


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO())


class _State:
    mode = "ok"  # ok | error | malformed


def _make_handler(state: _State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:  # silence server logging
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)  # consume request body

            if state.mode == "error":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error":"boom"}')
                return
            if state.mode == "malformed":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"not-json-at-all")
                return

            body = json.dumps({"choices": [{"message": {"content": json.dumps(_ENRICHMENT)}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    return Handler


@pytest.fixture
def ai_server() -> Iterator[tuple[str, _State]]:
    """Start a local OpenAI-compatible server; yield (base_url, state)."""
    state = _State()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()
