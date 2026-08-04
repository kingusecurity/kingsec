"""ActionExecutor: custom-webhook handling via the injected URLValidationPort.

Scoped to the webhook action specifically — this is the action that was
previously importing kingsec.infrastructure.notifications.url_validator
directly from the application layer (an import-linter violation). The rest
of ActionExecutor's handlers are pre-existing and untouched by this change.
"""

from __future__ import annotations

from unittest.mock import patch

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
        executor = ActionExecutor(url_validator=_AllowingValidator())
        with patch("urllib.request.urlopen") as mock_urlopen:
            log = executor.execute(_webhook_action("https://example.com/hook"), {})
        assert log.status == "completed"
        assert log.output is not None
        assert "Webhook sent to https://example.com/hook" in log.output
        mock_urlopen.assert_called_once()
