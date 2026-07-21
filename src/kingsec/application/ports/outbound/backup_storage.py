from __future__ import annotations

from abc import ABC, abstractmethod


class BackupStoragePort(ABC):
    @abstractmethod
    def write(self, backup_id: str, data: bytes) -> str: ...

    @abstractmethod
    def read(self, backup_id: str) -> bytes | None: ...

    @abstractmethod
    def delete(self, backup_id: str) -> bool: ...

    @abstractmethod
    def exists(self, backup_id: str) -> bool: ...

    @abstractmethod
    def size(self, backup_id: str) -> int: ...
