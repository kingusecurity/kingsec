from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)
from kingsec.infrastructure.notifications import url_validator as url_validator_module
from kingsec.infrastructure.notifications.senders import (
    DiscordSender,
    EmailSender,
    InAppSender,
    SlackSender,
    TeamsSender,
    WebhookSender,
)

from .test_url_validator import _redirect_handler_from_box, redirecting_server  # noqa: F401 - fixture reuse


def _make_notification(channel: NotificationChannel = NotificationChannel.IN_APP) -> Notification:
    return Notification(
        id=NotificationId("n1"),
        user_id="user1",
        title="Test",
        message="Hello",
        channel=channel,
        status=NotificationStatus.PENDING,
        priority=NotificationPriority.MEDIUM,
        event_type="test",
        template_vars={},
        retry_count=0,
        max_retries=3,
        created_at="now",
        updated_at="now",
    )


class TestEmailSender:
    def test_channel(self) -> None:
        assert EmailSender().channel() == "email"

    def test_send_no_config_returns_none(self) -> None:
        result = EmailSender().send(_make_notification(NotificationChannel.EMAIL))
        assert result is None


class TestWebhookSender:
    def test_channel(self) -> None:
        assert WebhookSender().channel() == "webhook"

    def test_send_no_endpoint_returns_error(self) -> None:
        result = WebhookSender().send(_make_notification(NotificationChannel.WEBHOOK))
        assert result == "Webhook endpoint not configured"


class TestSlackSender:
    def test_channel(self) -> None:
        assert SlackSender().channel() == "slack"

    def test_send_no_webhook_returns_error(self) -> None:
        result = SlackSender().send(_make_notification(NotificationChannel.SLACK))
        assert result == "Slack webhook not configured"


class TestDiscordSender:
    def test_channel(self) -> None:
        assert DiscordSender().channel() == "discord"

    def test_send_no_webhook_returns_error(self) -> None:
        result = DiscordSender().send(_make_notification(NotificationChannel.DISCORD))
        assert result == "Discord webhook not configured"


class TestTeamsSender:
    def test_channel(self) -> None:
        assert TeamsSender().channel() == "microsoft_teams"

    def test_send_no_webhook_returns_error(self) -> None:
        result = TeamsSender().send(_make_notification(NotificationChannel.MICROSOFT_TEAMS))
        assert result == "Teams webhook not configured"


class TestInAppSender:
    def test_channel(self) -> None:
        assert InAppSender().channel() == "in_app"

    def test_send_returns_none(self) -> None:
        result = InAppSender().send(_make_notification(NotificationChannel.IN_APP))
        assert result is None


# ── Phase 66 / Finding KSEC-64-02: SSRF-via-redirect regression tests ──────
#
# WebhookSender/SlackSender/DiscordSender/TeamsSender previously called
# validate_url() (checks only the *initial* URL) and then a plain
# urlopen() (follows redirects with the default opener) - a destination
# that passed that initial check could redirect the connection to an
# internal/private address after the fact. The fix switches all four
# senders to open_validated(), which refuses to follow any redirect at
# all - the same mechanism test_url_validator.py's own
# TestOpenValidatedRefusesRedirects already proves against the bare
# open_validated() function. These tests prove the same property holds
# through the real, concrete sender classes end to end, using real local
# HTTP servers (never a mocked urlopen, never real external
# infrastructure).


class _RecordingHandler(BaseHTTPRequestHandler):
    hits: list[str]

    def log_message(self, *_args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.hits.append(self.path)
        self.send_response(200)
        self.end_headers()


def _make_recording_handler(hits: list[str]) -> type[BaseHTTPRequestHandler]:
    class Handler(_RecordingHandler):
        pass

    Handler.hits = hits
    return Handler


@pytest.fixture
def recording_server() -> Iterator[tuple[str, list[str]]]:
    """A local server that records every request it receives - stands in
    for both a legitimate notification endpoint (positive test) and the
    dangerous internal target a redirect must never reach (negative
    test): its hit list proves whether it was ever actually contacted,
    which is stronger evidence than merely asserting an exception."""
    hits: list[str] = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_recording_handler(hits))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", hits
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def allow_local_test_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production senders.py always targets genuine public destination
    URLs and never passes an allowlist to open_validated(). Every local
    test server in this file necessarily binds to loopback, so this
    fixture patches senders.py's open_validated reference to allowlist
    ONLY the *initial* request's own hostname - exactly mirroring the
    allowlist technique test_url_validator.py's TestOpenValidatedRefusesRedirects
    already uses to isolate "does redirect-refusal work" from "does
    initial-URL validation work" (a separate, already-covered concern).
    A redirect target's hostname/IP is never added to this allowlist, so
    the real, unconditional _NoRedirectHandler refusal remains exactly
    what every test below exercises."""
    real_open_validated = url_validator_module.open_validated

    def patched(req, *, timeout, **kwargs):  # type: ignore[no-untyped-def]
        hostname = urlparse(req.full_url).hostname
        return real_open_validated(req, timeout=timeout, allowlist=[hostname], **kwargs)

    monkeypatch.setattr("kingsec.infrastructure.notifications.senders.open_validated", patched)


@pytest.fixture
def redirect_source(redirecting_server: tuple[str, list]) -> tuple[str, list]:  # noqa: F811 - pytest fixture injection requires this exact parameter name to match the imported fixture; re-exported under a distinct name below so other tests don't repeat the same import-shadowing pattern
    """Thin re-export of test_url_validator.py's redirecting_server
    fixture under a distinct name for use elsewhere in this file."""
    return redirecting_server


_SENDER_FACTORIES = [
    pytest.param(lambda url: WebhookSender(endpoint=url), NotificationChannel.WEBHOOK, id="webhook"),
    pytest.param(lambda url: SlackSender(webhook_url=url), NotificationChannel.SLACK, id="slack"),
    pytest.param(lambda url: DiscordSender(webhook_url=url), NotificationChannel.DISCORD, id="discord"),
    pytest.param(lambda url: TeamsSender(webhook_url=url), NotificationChannel.MICROSOFT_TEAMS, id="teams"),
]


@pytest.mark.usefixtures("allow_local_test_servers")
class TestSenderSSRFRedirectProtection:
    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_normal_delivery_to_a_direct_endpoint_still_succeeds(
        self, make_sender, channel, recording_server: tuple[str, list[str]]
    ) -> None:
        """Functionality preservation: an allowed, non-redirecting
        destination must still receive the notification."""
        url, hits = recording_server
        sender = make_sender(url)
        result = sender.send(_make_notification(channel))
        assert result is None, result
        assert len(hits) == 1

    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_redirect_to_loopback_is_refused_and_target_receives_nothing(
        self,
        make_sender,
        channel,
        redirect_source: tuple[str, list],
        recording_server: tuple[str, list[str]],
    ) -> None:
        """The negative security test required by Phase 66 Sec.11: the
        dangerous target is a real, reachable local server, and its hit
        list proves it received ZERO requests - not merely that an
        exception was raised somewhere."""
        redirect_base, box = redirect_source
        dangerous_url, dangerous_hits = recording_server
        box[0] = dangerous_url
        sender = make_sender(redirect_base)
        result = sender.send(_make_notification(channel))
        assert result == "URL blocked by SSRF protection", result
        assert dangerous_hits == []

    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_redirect_to_rfc1918_private_address_is_refused(
        self, make_sender, channel, redirect_source: tuple[str, list]
    ) -> None:
        redirect_base, box = redirect_source
        box[0] = "http://10.1.2.3/internal"
        sender = make_sender(redirect_base)
        result = sender.send(_make_notification(channel))
        assert result == "URL blocked by SSRF protection", result

    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_redirect_to_link_local_metadata_address_is_refused(
        self, make_sender, channel, redirect_source: tuple[str, list]
    ) -> None:
        """169.254.169.254 is the canonical cloud-metadata SSRF target."""
        redirect_base, box = redirect_source
        box[0] = "http://169.254.169.254/latest/meta-data/"
        sender = make_sender(redirect_base)
        result = sender.send(_make_notification(channel))
        assert result == "URL blocked by SSRF protection", result

    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_redirect_to_ipv6_loopback_is_refused(
        self, make_sender, channel, redirect_source: tuple[str, list]
    ) -> None:
        redirect_base, box = redirect_source
        box[0] = "http://[::1]:1/internal"
        sender = make_sender(redirect_base)
        result = sender.send(_make_notification(channel))
        assert result == "URL blocked by SSRF protection", result

    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_redirect_chain_through_a_second_public_looking_host_never_reaches_the_private_target(
        self, make_sender, channel, recording_server: tuple[str, list[str]]
    ) -> None:
        """public -> public -> private: server A (public-looking)
        redirects to server B (also public-looking), which would in turn
        redirect to the dangerous target - but refusal happens at the
        very first hop, so neither B nor the dangerous target ever
        receives a request."""
        dangerous_url, dangerous_hits = recording_server

        b_box: list[str] = [dangerous_url]
        server_b = ThreadingHTTPServer(("127.0.0.1", 0), _redirect_handler_from_box(b_box))
        threading.Thread(target=server_b.serve_forever, daemon=True).start()
        b_host, b_port = server_b.server_address
        b_url = f"http://{b_host}:{b_port}"
        try:
            a_box: list[str] = [b_url]
            server_a = ThreadingHTTPServer(("127.0.0.1", 0), _redirect_handler_from_box(a_box))
            threading.Thread(target=server_a.serve_forever, daemon=True).start()
            a_host, a_port = server_a.server_address
            try:
                sender = make_sender(f"http://{a_host}:{a_port}")
                result = sender.send(_make_notification(channel))
                assert result == "URL blocked by SSRF protection", result
                assert dangerous_hits == []
            finally:
                server_a.shutdown()
                server_a.server_close()
        finally:
            server_b.shutdown()
            server_b.server_close()

    @pytest.mark.parametrize("make_sender,channel", _SENDER_FACTORIES)
    def test_malformed_redirect_location_fails_safely(self, make_sender, channel) -> None:
        """A 302 with a syntactically broken Location header must not
        crash uncontrolled or be silently followed - send() must return
        a handled error string, not raise."""
        box: list[str] = ["http://[not-a-valid-host/broken"]
        server = ThreadingHTTPServer(("127.0.0.1", 0), _redirect_handler_from_box(box))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        host, port = server.server_address
        try:
            sender = make_sender(f"http://{host}:{port}")
            result = sender.send(_make_notification(channel))
            assert result is not None
        finally:
            server.shutdown()
            server.server_close()
