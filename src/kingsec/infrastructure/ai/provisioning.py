"""Dependency-injection wiring for the AI adapter.

``register_ai`` builds the client + adapter from configuration and binds the
Nuclei-style ``AIPort`` on the Module 2.4 container, registering the client's
``close`` as a shutdown hook so the connection pool is released cleanly. It takes
the container duck-typed, so infrastructure never imports the bootstrap layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from kingsec.application import AIPort
from kingsec.infrastructure.logging import get_logger

from .adapter import AIProviderAdapter
from .client import AIClient
from .providers import resolve_provider

if TYPE_CHECKING:  # typing only
    from kingsec.infrastructure.config import Settings

_logger = get_logger("kingsec.infrastructure.ai")


def register_ai(
    container: object,
    settings: Settings,
    *,
    transport: httpx.BaseTransport | None = None,
) -> AIPort:
    """Build and register the AI enrichment adapter as ``AIPort``.

    Args:
        container: The bootstrap DI container (duck-typed: needs
            ``register_instance`` and ``add_shutdown_hook``).
        settings: Application settings (uses ``settings.ai``).
        transport: Optional httpx transport override (tests inject a mock).

    Returns:
        The registered ``AIPort`` implementation.
    """
    ai_settings = settings.ai
    provider = resolve_provider(ai_settings.provider)  # fails fast on bad provider
    client = AIClient(
        timeout=ai_settings.request_timeout_seconds,
        retry_count=ai_settings.retry_count,
        retry_delay=ai_settings.retry_delay,
        verify_ssl=ai_settings.verify_ssl,
        transport=transport,
    )
    adapter = AIProviderAdapter(settings=ai_settings, provider=provider, client=client)

    register = container.register_instance
    register(AIPort, adapter)
    add_shutdown_hook = getattr(container, "add_shutdown_hook", None)
    if callable(add_shutdown_hook):
        add_shutdown_hook(client.close)

    _logger.info("ai adapter registered", provider=ai_settings.provider)
    return adapter
