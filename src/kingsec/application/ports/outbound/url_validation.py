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
