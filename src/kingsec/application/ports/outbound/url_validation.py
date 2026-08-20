"""Port for URL safety validation — application layer contract.

The ``URLValidationPort`` defines how the application checks whether a URL
is safe to fetch (e.g. before an outbound webhook call) before performing
the request. Infrastructure implements this port with real SSRF protection
(private/loopback/link-local/reserved address blocking); the application
never imports that validation logic directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class UnsafeURLError(Exception):
    """Raised when a URL is blocked by safety validation (e.g. SSRF protection)."""


class URLValidationPort(ABC):
    """Abstract port for validating that a URL is safe to fetch."""

    @abstractmethod
    def validate(self, url: str) -> None:
        """Validate that ``url`` is safe to open.

        Args:
            url: The URL to validate.

        Raises:
            UnsafeURLError: If the URL targets a private/reserved address,
                uses a disallowed scheme, or cannot be resolved.
        """

    @abstractmethod
    def open(
        self,
        url: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float,
    ) -> None:
        """Validate ``url``, then perform the HTTP request, refusing any redirect.

        For fire-and-forget delivery calls (e.g. a webhook POST) where only
        success or failure matters - the response body is never returned.
        A destination that passes ``validate()`` but later responds with a
        redirect is exactly as unsafe as one that fails validation outright
        (the redirect target was never itself validated), so this refuses
        to follow it rather than silently re-validating and continuing.

        Args:
            url: The URL to validate and open.
            method: The HTTP method to use.
            data: Optional request body.
            headers: Optional request headers.
            timeout: Request timeout in seconds.

        Raises:
            UnsafeURLError: If ``url`` fails validation, or the destination
                attempts to redirect the request anywhere.
        """
