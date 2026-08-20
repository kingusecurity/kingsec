"""Port for testing a candidate AI provider configuration.

Distinct from ``AIQueryPort`` (chat/generate/health against the currently
*configured* provider): this port exists for the AI Provider Settings UI's
"test before you save" flow, which must exercise arbitrary, not-yet-saved
credentials (provider name, API key, model, base URL) supplied directly in
the request - a configuration ``AIConfigResolver`` never sees, since it only
ever resolves what is already saved or set via environment.

Infrastructure implements this with the same per-provider wire-format
strategies (``infrastructure/ai/providers.py``) and pooled HTTP client
(``infrastructure/ai/client.py``) used everywhere else in this codebase;
the application layer never imports either directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class AIProviderTestPort(ABC):
    """Abstract port for validating and test-driving a candidate AI provider config."""

    @abstractmethod
    def validate_provider(self, provider: str) -> None:
        """Raise if ``provider`` is not a supported AI provider name.

        Args:
            provider: The provider name to check (case-insensitive).

        Raises:
            kingsec.shared.errors.ExternalServiceError: If unsupported.
        """

    @abstractmethod
    def default_model_for(self, provider: str) -> str:
        """Return a sensible default model name for ``provider``.

        Never raises - falls back to a safe default for an unrecognised
        provider name (this is a display/request-building convenience,
        not a validation check; callers that need strict validation use
        ``validate_provider`` first).
        """

    @abstractmethod
    def test_connection(
        self,
        provider: str,
        api_key: str,
        model: str | None,
        base_url: str | None,
    ) -> str:
        """Make one real, minimal connectivity call with the given candidate credentials.

        Args:
            provider: The provider name (case-insensitive).
            api_key: The candidate API key to test - never logged, never persisted.
            model: The model to request; a provider-appropriate default is
                used if omitted.
            base_url: The endpoint base URL; the provider's own default is
                used if omitted.

        Returns:
            The provider's display name, on success.

        Raises:
            kingsec.shared.errors.ExternalServiceError: If the provider name
                is unsupported or the connectivity test itself fails
                (auth, network, timeout, or malformed response).
        """
