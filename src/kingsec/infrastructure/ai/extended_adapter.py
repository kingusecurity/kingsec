from __future__ import annotations

from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.infrastructure.ai.adapter import AIProviderAdapter
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.ai")


class ExtendedAIAdapter(AIQueryPort):
    """Extended AI adapter that wraps AIProviderAdapter for chat, generate, health."""

    def __init__(self, adapter: AIProviderAdapter, audit: Any = None) -> None:
        self._adapter = adapter
        self._audit = audit

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        api_key = self._adapter._require_api_key()
        settings = self._adapter._settings
        provider = self._adapter._provider
        client = self._adapter._client
        base_url = settings.base_url or provider.default_base_url
        model = kwargs.get("model", settings.model)
        temperature = kwargs.get("temperature", settings.temperature)
        max_tokens = kwargs.get("max_tokens", settings.max_tokens + 1024)

        url = provider.build_endpoint(base_url, model)
        headers = provider.build_headers(api_key)
        payload = provider.build_payload(system_prompt, user_prompt, model, temperature, max_tokens)

        _logger.info("ai generate requested", provider=settings.provider, model=model)
        response = client.post_json(url, headers, payload)
        text = provider.extract_text(response)
        self._audit_request(settings.provider, model, "generate")
        return text

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        api_key = self._adapter._require_api_key()
        settings = self._adapter._settings
        provider = self._adapter._provider
        client = self._adapter._client
        base_url = settings.base_url or provider.default_base_url
        model = kwargs.get("model", settings.model)
        temperature = kwargs.get("temperature", settings.temperature)
        max_tokens = kwargs.get("max_tokens", settings.max_tokens + 1024)

        url = provider.build_endpoint(base_url, model)

        system = ""
        chat_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system = system + "\n" + msg["content"] if system else msg["content"]
            else:
                chat_messages.append(msg)

        headers = provider.build_headers(api_key)
        payload = provider.build_payload(system, chat_messages[-1]["content"] if chat_messages else "", model, temperature, max_tokens)

        _logger.info("ai chat requested", provider=settings.provider, model=model)
        response = client.post_json(url, headers, payload)
        text = provider.extract_text(response)
        self._audit_request(settings.provider, model, "chat")
        return text

    def health(self) -> dict[str, Any]:
        try:
            result = self.generate("Respond with only the word OK.", "Status check", max_tokens=10)
            available = bool(result and result.strip())
        except Exception as exc:
            _logger.warning("ai health check failed", error=str(exc))
            return {
                "available": False,
                "provider": self._adapter._settings.provider,
                "error": str(exc),
            }
        return {
            "available": available,
            "provider": self._adapter._settings.provider,
            "model": self._adapter._settings.model,
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
        except Exception:
            pass
