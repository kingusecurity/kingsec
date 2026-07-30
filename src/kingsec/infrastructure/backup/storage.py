from __future__ import annotations

import re
from pathlib import Path

from kingsec.application.ports.outbound import BackupStoragePort

_SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _validate_id(backup_id: str) -> None:
    """Reject IDs containing path traversal or special characters."""
    if not backup_id or not _SAFE_ID_PATTERN.match(backup_id):
        raise ValueError(f"Invalid backup ID: {backup_id!r}")


class FilesystemBackupStorage(BackupStoragePort):
    def __init__(self, base_path: str | Path = "backups") -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def write(self, backup_id: str, data: bytes) -> str:
        _validate_id(backup_id)
        path = self._base / f"{backup_id}.bkp"
        path.write_bytes(data)
        return str(path)

    def read(self, backup_id: str) -> bytes | None:
        _validate_id(backup_id)
        path = self._base / f"{backup_id}.bkp"
        if not path.exists():
            return None
        return path.read_bytes()

    def delete(self, backup_id: str) -> bool:
        _validate_id(backup_id)
        path = self._base / f"{backup_id}.bkp"
        if path.exists():
            path.unlink()
            return True
        return False

    def exists(self, backup_id: str) -> bool:
        _validate_id(backup_id)
        return (self._base / f"{backup_id}.bkp").exists()

    def size(self, backup_id: str) -> int:
        _validate_id(backup_id)
        path = self._base / f"{backup_id}.bkp"
        return path.stat().st_size if path.exists() else 0
