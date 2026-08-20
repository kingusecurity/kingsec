"""AI adapter errors and the httpx -> AIError translation boundary.

``AIError`` subclasses the shared kernel's ``ExternalServiceError`` (code
KS-EXT-001), so it is a stable, safe, application-facing error that flows through
the existing exception handling. Crucially, NO ``httpx`` exception is ever
allowed to escape this package: :class:`ErrorTranslator` converts every transport
failure and error status code into an ``AIError`` subtype. The application only
ever sees ``AIError``.
"""

from __future__ import annotations

import httpx

from kingsec.shared.errors import ExternalServiceError


class AIError(ExternalServiceError):
    """The AI provider could not be reached or returned an error."""


class AITimeoutError(AIError):
    """The AI request exceeded its timeout."""


class AIAuthenticationError(AIError):
    """The AI provider rejected the credentials (401/403), or none were set."""


class AIRateLimitError(AIError):
    """The AI provider rate-limited the request (429)."""


class AIResponseError(AIError):
    """The AI provider replied, but the body could not be parsed/used."""


class AIUnsafeURLError(AIError):
    """base_url failed SSRF validation before any request was attempted."""


# HTTP status codes worth retrying (transient server/throttling conditions).
RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})


class ErrorTranslator:
    """Translates httpx failures and error responses into ``AIError`` subtypes."""

    @staticmethod
    def from_exception(exc: Exception) -> AIError:
        """Map a transport-level exception to an ``AIError``.

        Args:
            exc: The exception raised by httpx (or JSON decoding).

        Returns:
            The corresponding ``AIError`` subtype.
        """
        if isinstance(exc, httpx.TimeoutException):
            return AITimeoutError("AI request timed out", cause=exc)
        if isinstance(exc, httpx.TransportError):
            return AIError("AI transport error", cause=exc)
        return AIError("AI request failed", cause=exc)

    @staticmethod
    def from_status(status_code: int, body: str) -> AIError:
        """Map an HTTP error status to an ``AIError``.

        The response body is truncated into log-safe context; it is provider
        detail for operators, never surfaced to end users.

        Args:
            status_code: The HTTP status code returned by the provider.
            body: The (possibly large) response body text.

        Returns:
            The corresponding ``AIError`` subtype.
        """
        context = {"status": status_code, "body": body.strip()[:200]}
        if status_code in (401, 403):
            return AIAuthenticationError("AI authentication failed", context=context)
        if status_code == 429:
            return AIRateLimitError("AI rate limit exceeded", context=context)
        return AIError(f"AI request failed with status {status_code}", context=context)
