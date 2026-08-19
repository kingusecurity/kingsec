"""ActionExecutor: custom-webhook handling via the injected URLValidationPort.

Scoped to the webhook action specifically — this is the action that was
previously importing kingsec.infrastructure.notifications.url_validator
directly from the application layer (an import-linter violation). The rest
of ActionExecutor's handlers are pre-existing and untouched by this change.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest

from kingsec.application.playbooks.actions import ActionExecutor
from kingsec.application.ports import UnsafeURLError, URLValidationPort
from kingsec.domain.playbook import PlaybookAction, PlaybookActionType


class _AllowingValidator(URLValidationPort):
    def validate(self, url: str) -> None:
        return None


class _BlockingValidator(URLValidationPort):
    def validate(self, url: str) -> None:
        raise UnsafeURLError(f"blocked: {url}")


def _webhook_action(url: str) -> PlaybookAction:
    return PlaybookAction(
        action_type=PlaybookActionType.CUSTOM_WEBHOOK,
        config={"url": url, "payload": {"key": "value"}},
    )


def _redirect_handler_from_box(box: list) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:  # silence server logging
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(302)
            self.send_header("Location", box[0])
            self.end_headers()

    return Handler


@pytest.fixture
def redirecting_webhook_server() -> Iterator[tuple[str, list]]:
    """A local server that always 302-redirects to a caller-set target
    (mirrors tests/unit/infrastructure/test_url_validator.py's identical
    fixture, duplicated here for the same reason _NoRedirectHandler itself
    is duplicated: this test module covers the application layer)."""
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


class TestWebhookURLValidation:
    def test_no_validator_injected_is_unavailable(self) -> None:
        # Mirrors the sibling handlers' "<service> not available" pattern
        # when their port dependency wasn't wired.
        executor = ActionExecutor()  # url_validator defaults to None
        log = executor.execute(_webhook_action("http://example.com/hook"), {})
        assert log.status == "completed"
        assert log.output is not None
        assert "URL validation service not available" in log.output

    def test_blocked_url_fails_the_action(self) -> None:
        executor = ActionExecutor(url_validator=_BlockingValidator())
        log = executor.execute(_webhook_action("http://169.254.169.254/latest"), {})
        assert log.status == "failed"
        assert log.error is not None
        assert "blocked by SSRF protection" in log.error

    def test_allowed_url_proceeds_to_send(self) -> None:
        # Phase 12: _handle_webhook no longer calls urllib.request.urlopen()
        # directly - it opens through a module-level _NO_REDIRECT_OPENER
        # that refuses to follow HTTP redirects (closing the gap where a
        # destination already validated by URLValidationPort could redirect
        # the connection to an unvalidated address). Patching the old
        # target here would silently fall through to a REAL network call -
        # confirmed live: the original assertion failed with a genuine
        # HTTPError from example.com before this fix, not a passing mock.
        executor = ActionExecutor(url_validator=_AllowingValidator())
        with patch("kingsec.application.playbooks.actions._NO_REDIRECT_OPENER.open") as mock_open:
            log = executor.execute(_webhook_action("https://example.com/hook"), {})
        assert log.status == "completed"
        assert log.output is not None
        assert "Webhook sent to https://example.com/hook" in log.output
        mock_open.assert_called_once()

    def test_redirect_is_refused_not_followed(self, redirecting_webhook_server: tuple[str, list]) -> None:
        """The gap Phase 12 closes: URLValidationPort only validates the
        initial URL, so following a redirect without re-validating it would
        let an already-validated webhook destination redirect the request
        to an internal address. Exercises the real, local
        _NO_REDIRECT_OPENER (application layer's own duplicated
        _NoRedirectHandler, not infrastructure's) against a real HTTP 302,
        not a mocked exception."""
        base_url, box = redirecting_webhook_server
        box[0] = "http://169.254.169.254/latest/meta-data/"
        executor = ActionExecutor(url_validator=_AllowingValidator())
        log = executor.execute(_webhook_action(base_url), {})
        assert log.status == "failed"
        assert log.error is not None
        assert "blocked by SSRF protection" in log.error
        assert "refusing to follow redirect" in log.error
