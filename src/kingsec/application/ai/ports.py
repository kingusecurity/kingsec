from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AIQueryPort(ABC):
    """Extended AI port for chat, summarization, and general queries.

    Unlike ``AIPort`` (single finding enrichment), this port supports
    multi-turn chat, structured summaries, and health checks.
    """

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        """Send a prompt pair and return the generated text."""

    @abstractmethod
    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        """Send a multi-turn conversation and return the assistant response."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Check provider connectivity and return status info."""
