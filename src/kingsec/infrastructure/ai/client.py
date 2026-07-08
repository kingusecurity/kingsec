"""The HTTP client for AI providers — the only module that imports httpx.

Responsibilities: connection pooling, timeouts, TLS verification, retry with
exponential back-off on transient failures, structured logging, and translating
every httpx failure into an ``AIError`` so no ``httpx`` exception escapes
infrastructure. It logs metadata only — never the API key (it lives in caller
headers) and never the prompt body (which may echo scanner data).
"""

from __future__ import annotations

import json
import time

import httpx

from kingsec.infrastructure.logging import get_logger

from .errors import RETRYABLE_STATUS_CODES, AIResponseError, ErrorTranslator

_logger = get_logger("kingsec.infrastructure.ai")


class AIClient:
    """A pooled, retrying, TLS-verifying JSON-over-HTTP client for AI providers."""

    def __init__(
        self,
        *,
        timeout: float,
        retry_count: int,
        retry_delay: float,
        verify_ssl: bool = True,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialise the client.

        Args:
            timeout: Per-request timeout in seconds.
            retry_count: Number of retries after the initial attempt (>= 0).
            retry_delay: Base back-off delay in seconds (exponential per attempt).
            verify_ssl: Whether to verify TLS certificates. Secure by default;
                only an explicit False disables verification.
            transport: Optional transport override (tests inject a mock).
        """

        self._retry_count = max(0, retry_count)
        self._retry_delay = max(0.0, retry_delay)
        # A single pooled client is reused for all requests (keep-alive).
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            verify=verify_ssl,
            transport=transport,
        )

    def post_json(self, url: str, headers: dict[str, str], payload: dict) -> dict:
        """POST a JSON payload and return the parsed JSON response.

        Retries transient transport errors and retryable status codes with
        exponential back-off, then translates any remaining failure.

        Args:
            url: The endpoint URL.
            headers: Request headers (including auth — never logged).
            payload: The JSON request body.

        Returns:
            The parsed JSON response body.

        Raises:
            AIError: On timeout, transport failure, error status, or unparseable
                body. (One of its subtypes.)
        """

        attempts = self._retry_count + 1
        for attempt in range(1, attempts + 1):
            try:
                response = self._client.post(url, headers=headers, json=payload)
            except httpx.HTTPError as exc:
                if attempt <= self._retry_count:
                    _logger.warning(
                        "ai request retry", attempt=attempt, reason=type(exc).__name__
                    )
                    self._backoff(attempt)
                    continue
                raise ErrorTranslator.from_exception(exc) from exc

            if response.status_code >= 400:
                if (
                    response.status_code in RETRYABLE_STATUS_CODES
                    and attempt <= self._retry_count
                ):
                    _logger.warning(
                        "ai request retry", attempt=attempt, status=response.status_code
                    )
                    self._backoff(attempt)
                    continue
                raise ErrorTranslator.from_status(response.status_code, response.text)

            try:
                return response.json()
            except (json.JSONDecodeError, ValueError) as exc:
                raise AIResponseError(
                    "AI response body was not valid JSON", cause=exc
                ) from exc

        # Unreachable: the loop always returns or raises.
        raise AIResponseError("AI request exhausted retries")  # pragma: no cover

    def _backoff(self, attempt: int) -> None:
        """Sleep with exponential back-off before the next attempt."""

        if self._retry_delay > 0:
            time.sleep(self._retry_delay * (2 ** (attempt - 1)))

    def close(self) -> None:
        """Close the underlying connection pool (registered as a shutdown hook)."""

        self._client.close()
