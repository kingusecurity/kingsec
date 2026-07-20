from __future__ import annotations

import os
from pathlib import Path

from kingsec.application.ports.outbound import BackupStoragePort


class FilesystemBackupStorage(BackupStoragePort):
    def __init__(self, base_path: str | Path = "backups") -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def write(self, backup_id: str, data: bytes) -> str:
        path = self._base / f"{backup_id}.bkp"
        path.write_bytes(data)
        return str(path)

    def read(self, backup_id: str) -> bytes | None:
        path = self._base / f"{backup_id}.bkp"
        if not path.exists():
            return None
        return path.read_bytes()

    def delete(self, backup_id: str) -> bool:
        path = self._base / f"{backup_id}.bkp"
        if path.exists():
            path.unlink()
            return True
        return False

    def exists(self, backup_id: str) -> bool:
        return (self._base / f"{backup_id}.bkp").exists()

    def size(self, backup_id: str) -> int:
        path = self._base / f"{backup_id}.bkp"
        return path.stat().st_size if path.exists() else 0
