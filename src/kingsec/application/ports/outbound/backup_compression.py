from __future__ import annotations

from abc import ABC, abstractmethod


class BackupCompressionPort(ABC):
    @abstractmethod
    def compress(self, data: bytes) -> bytes: ...

    @abstractmethod
    def decompress(self, data: bytes) -> bytes: ...
