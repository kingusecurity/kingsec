"""Implements ``AIProviderTestPort`` — the AI Provider Settings "test before
you save" flow, moved out of the web adapter layer.

Reuses the same per-provider wire-format strategies (``providers.py``) and
pooled HTTP client (``client.py``) as the rest of this codebase's AI
integration; nothing here is new logic, only a new home for logic that used
to live directly in ``adapters/inbound/web/ai_provider_routes.py``.
"""

from __future__ import annotations

from kingsec.application.ports import UnsafeURLError, URLValidationPort
from kingsec.application.ports.outbound.ai_provider_test import AIProviderTestPort

from .client import AIClient
from .errors import AIUnsafeURLError
from .providers import default_model_for, resolve_provider


class AIProviderTester(AIProviderTestPort):
    """Validates provider names and test-drives candidate AI provider configs."""

    def __init__(self, url_validator: URLValidationPort) -> None:
        """Args:
        url_validator: Validates a caller-supplied base_url before it is
            used to build an outbound request. Every base_url this method
            sees is request input by definition (it is a parameter of this
            call, not deployment configuration), so it is always validated
            when present - unlike AIProviderAdapter, which only validates
            the database-sourced case.
        """
        self._url_validator = url_validator

    def validate_provider(self, provider: str) -> None:
        resolve_provider(provider)  # raises AIError (an ExternalServiceError) if unsupported

    def default_model_for(self, provider: str) -> str:
        return default_model_for(provider)

    def test_connection(
        self,
        provider: str,
        api_key: str,
        model: str | None,
        base_url: str | None,
    ) -> str:
        strategy = resolve_provider(provider)
        resolved_model = model or default_model_for(provider)
        resolved_base_url = base_url or strategy.default_base_url

        if base_url:
            try:
                self._url_validator.validate(base_url)
            except UnsafeURLError as exc:
                raise AIUnsafeURLError(f"AI base_url blocked by SSRF protection: {exc}") from exc

        client = AIClient(timeout=15, retry_count=0, retry_delay=0, verify_ssl=True)
        try:
            url = strategy.build_endpoint(resolved_base_url, resolved_model)
            headers = strategy.build_headers(api_key)
            payload = strategy.build_payload(
                "You are a connectivity test. Reply with exactly one word.",
                "Reply with the single word: OK",
                resolved_model,
                0.0,
                8,
            )
            strategy.extract_text(client.post_json(url, headers, payload))
        finally:
            client.close()

        return strategy.name
