"""Port for secret storage — no infrastructure imports."""

from __future__ import annotations

from abc import ABC, abstractmethod


class SecretProviderPort(ABC):
    @abstractmethod
    def get(self, name: str) -> str | None:
        ...

    @abstractmethod
    def set(self, name: str, value: str) -> None:
        ...

    @abstractmethod
    def exists(self, name: str) -> bool:
        ...

    @abstractmethod
    def delete(self, name: str) -> None:
        ...

    @abstractmethod
    def list(self) -> list[str]:
        ...
