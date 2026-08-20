"""ActionExecutor: custom-webhook handling via the injected URLValidationPort.

Scoped to the webhook action specifically — this is the action that was
previously importing kingsec.infrastructure.notifications.url_validator
directly from the application layer (an import-linter violation). The rest
of ActionExecutor's handlers are pre-existing and untouched by this change.

Phase 13: URLValidationPort gained an open() method (validate + perform,
refusing redirects) so this file's own previously-duplicated
_NoRedirectHandler could be deleted in favour of the single canonical
implementation in infrastructure/notifications/url_validator.py. The stub
validators below now implement open() directly (mirroring what a real
implementation does internally: validate, then either perform the request
or raise) rather than testing a redirect-refusal mechanism that used to
live in this module and no longer does - that mechanism's own correctness
is covered end-to-end, against a real local server, in
tests/unit/infrastructure/test_url_validator.py. This file's own redirect
test now uses the REAL SSRFURLValidator (not a stub) to prove the unified
path still works from ActionExecutor's perspective, per this phase's own
requirement that this proof continue to exist in some form.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kingsec.application.playbooks.actions import ActionExecutor
from kingsec.application.ports import UnsafeURLError, URLValidationPort
from kingsec.domain.playbook import PlaybookAction, PlaybookActionType
from kingsec.infrastructure.notifications.url_validator import SSRFURLValidator


class _AllowingValidator(URLValidationPort):
    """A stub whose open() succeeds and records the call, without making a
    real network request - proves _handle_webhook wires success through
    correctly without needing a real server for every test."""

    def __init__(self) -> None:
        self.opened: list[dict[str, object]] = []

    def validate(self, url: str) -> None:
        return None

    def open(self, url: str, *, method: str = "GET", data=None, headers=None, timeout: float) -> None:
        self.opened.append({"url": url, "method": method, "data": data, "headers": headers, "timeout": timeout})


class _BlockingValidator(URLValidationPort):
    """A stub whose open() always raises - simulating a URL that fails
    SSRF validation. From _handle_webhook's perspective, this and a
    redirect refusal look identical: both are UnsafeURLError raised by
    open()."""

    def validate(self, url: str) -> None:
        raise UnsafeURLError(f"blocked: {url}")

    def open(self, url: str, *, method: str = "GET", data=None, headers=None, timeout: float) -> None:
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
        # Phase 13: _handle_webhook calls url_validator.open() (which
        # validates AND performs the request, refusing redirects) instead
        # of validate() + a separately-opened connection. The stub records
        # the call rather than needing a patch target inside the module -
        # there is no module-level opener object left to patch after
        # unification onto the single canonical URLValidationPort.open().
        validator = _AllowingValidator()
        executor = ActionExecutor(url_validator=validator)
        log = executor.execute(_webhook_action("https://example.com/hook"), {})
        assert log.status == "completed"
        assert log.output is not None
        assert "Webhook sent to https://example.com/hook" in log.output
        assert len(validator.opened) == 1
        assert validator.opened[0]["url"] == "https://example.com/hook"
        assert validator.opened[0]["method"] == "POST"

    def test_redirect_is_refused_not_followed(self, redirecting_webhook_server: tuple[str, list]) -> None:
        """Phase 13: proves the unified path still refuses redirects from
        ActionExecutor's perspective, per this phase's requirement that
        this proof continue to exist after unification. Uses the REAL
        SSRFURLValidator (not a stub) - the same class siem_service.py,
        ticketing_service.py, and webhook_service.py are wired to - so this
        is a genuine exercise of the single canonical implementation
        through this layer's own port injection, not a mock."""
        base_url, box = redirecting_webhook_server
        box[0] = "http://169.254.169.254/latest/meta-data/"
        executor = ActionExecutor(url_validator=SSRFURLValidator(allowlist=["127.0.0.1"]))
        log = executor.execute(_webhook_action(base_url), {})
        assert log.status == "failed"
        assert log.error is not None
        assert "blocked by SSRF protection" in log.error
        assert "refusing to follow redirect" in log.error
