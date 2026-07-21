"""Unit tests for AIClient: retries, timeouts, and error translation."""

from __future__ import annotations

import httpx
import pytest

from kingsec.infrastructure.ai import AIClient
from kingsec.infrastructure.ai.errors import (
    AIAuthenticationError,
    AIError,
    AIRateLimitError,
    AIResponseError,
    AITimeoutError,
)
from tests.unit.infrastructure.ai.conftest import sequence_transport


def _client(transport, *, retry_count: int = 2) -> AIClient:
    # retry_delay=0 keeps tests fast (no real back-off sleep).
    return AIClient(timeout=5, retry_count=retry_count, retry_delay=0, transport=transport)


_OK = httpx.Response(200, json={"ok": True})


class TestSuccess:
    def test_post_returns_parsed_json(self) -> None:
        client = _client(sequence_transport([_OK]))
        assert client.post_json("http://x", {}, {}) == {"ok": True}
        client.close()


class TestRetry:
    def test_retries_then_succeeds_on_503(self) -> None:
        transport = sequence_transport([httpx.Response(503), httpx.Response(503), _OK])
        client = _client(transport, retry_count=2)
        assert client.post_json("http://x", {}, {}) == {"ok": True}
        assert transport.calls["n"] == 3  # 2 retries + success
        client.close()

    def test_retries_then_succeeds_after_transport_error(self) -> None:
        transport = sequence_transport([httpx.ConnectError("boom"), _OK])
        client = _client(transport, retry_count=1)
        assert client.post_json("http://x", {}, {}) == {"ok": True}
        client.close()

    def test_retry_exhaustion_raises_ai_error(self) -> None:
        transport = sequence_transport([httpx.Response(503)] * 5)
        client = _client(transport, retry_count=2)
        with pytest.raises(AIError):
            client.post_json("http://x", {}, {})
        assert transport.calls["n"] == 3  # initial + 2 retries
        client.close()


class TestErrorTranslation:
    def test_timeout_becomes_ai_timeout_error(self) -> None:
        client = _client(sequence_transport([httpx.ReadTimeout("slow")]), retry_count=0)
        with pytest.raises(AITimeoutError):
            client.post_json("http://x", {}, {})
        client.close()

    def test_401_becomes_authentication_error(self) -> None:
        client = _client(sequence_transport([httpx.Response(401)]))
        with pytest.raises(AIAuthenticationError):
            client.post_json("http://x", {}, {})
        client.close()

    def test_403_is_not_retried(self) -> None:
        transport = sequence_transport([httpx.Response(403)] * 3)
        client = _client(transport, retry_count=2)
        with pytest.raises(AIAuthenticationError):
            client.post_json("http://x", {}, {})
        assert transport.calls["n"] == 1  # no retries on auth failure
        client.close()

    def test_429_becomes_rate_limit_error(self) -> None:
        # Exhaust retries so the final 429 surfaces as a rate-limit error.
        client = _client(sequence_transport([httpx.Response(429)] * 5), retry_count=1)
        with pytest.raises(AIRateLimitError):
            client.post_json("http://x", {}, {})
        client.close()

    def test_invalid_json_body_raises_response_error(self) -> None:
        transport = sequence_transport([httpx.Response(200, content=b"not json")])
        client = _client(transport, retry_count=0)
        with pytest.raises(AIResponseError):
            client.post_json("http://x", {}, {})
        client.close()

    def test_no_httpx_exception_escapes(self) -> None:
        client = _client(sequence_transport([httpx.ConnectError("x")]), retry_count=0)
        try:
            client.post_json("http://x", {}, {})
        except AIError:
            pass  # correct: translated
        except httpx.HTTPError:  # pragma: no cover
            pytest.fail("httpx exception leaked out of infrastructure")
        client.close()
