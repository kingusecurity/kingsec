from __future__ import annotations

from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.infrastructure.ai.adapter import AIProviderAdapter
from kingsec.infrastructure.ai.errors import AIAuthenticationError
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.ai")


class ExtendedAIAdapter(AIQueryPort):
    """Extended AI adapter that wraps AIProviderAdapter for chat, generate, health."""

    def __init__(self, adapter: AIProviderAdapter, audit: Any = None) -> None:
        self._adapter = adapter
        self._audit = audit

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        # Provider/key/model/base_url are resolved fresh per call (DB-saved
        # settings override env-var AISettings) - the same resolver
        # AIProviderAdapter._enrich() uses, so a Settings-page save takes
        # effect here too without a restart.
        resolved = self._adapter._config_resolver.resolve()
        if resolved.api_key is None:
            raise AIAuthenticationError("no AI API key configured")
        settings = self._adapter._settings
        base_url = resolved.base_url or resolved.provider.default_base_url
        model = kwargs.get("model", resolved.model)
        temperature = kwargs.get("temperature", settings.temperature)
        max_tokens = kwargs.get("max_tokens", settings.max_tokens + 1024)

        url = resolved.provider.build_endpoint(base_url, model)
        headers = resolved.provider.build_headers(resolved.api_key)
        payload = resolved.provider.build_payload(system_prompt, user_prompt, model, temperature, max_tokens)

        _logger.info("ai generate requested", provider=resolved.provider.name, model=model)
        response = self._adapter._client.post_json(url, headers, payload)
        text = resolved.provider.extract_text(response)
        self._audit_request(resolved.provider.name, model, "generate")
        return text

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        resolved = self._adapter._config_resolver.resolve()
        if resolved.api_key is None:
            raise AIAuthenticationError("no AI API key configured")
        settings = self._adapter._settings
        base_url = resolved.base_url or resolved.provider.default_base_url
        model = kwargs.get("model", resolved.model)
        temperature = kwargs.get("temperature", settings.temperature)
        max_tokens = kwargs.get("max_tokens", settings.max_tokens + 1024)

        system = ""
        chat_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system = system + "\n" + msg["content"] if system else msg["content"]
            else:
                chat_messages.append(msg)

        url = resolved.provider.build_endpoint(base_url, model)
        headers = resolved.provider.build_headers(resolved.api_key)
        payload = resolved.provider.build_payload(system, chat_messages[-1]["content"] if chat_messages else "", model, temperature, max_tokens)

        _logger.info("ai chat requested", provider=resolved.provider.name, model=model)
        response = self._adapter._client.post_json(url, headers, payload)
        text = resolved.provider.extract_text(response)
        self._audit_request(resolved.provider.name, model, "chat")
        return text

    def health(self) -> dict[str, Any]:
        resolved = self._adapter._config_resolver.resolve()
        try:
            result = self.generate("Respond with only the word OK.", "Status check", max_tokens=10)
            available = bool(result and result.strip())
        except Exception as exc:
            _logger.warning("ai health check failed", error=str(exc))
            return {
                "available": False,
                "provider": resolved.provider.name,
                "error": str(exc),
            }
        return {
            "available": available,
            "provider": resolved.provider.name,
            "model": resolved.model,
        }

    def _audit_request(self, provider: str, model: str, action: str) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(AuditEntry(
                action=AuditAction.INTEGRATION_CONNECTED,
                resource_type="ai_request",
                success=True,
                metadata={"provider": provider, "model": model, "action": action},
            ))
        except Exception as exc:
            _logger.warning("AI request audit entry failed (best-effort): %s", exc)
