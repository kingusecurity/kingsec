"""Secret provider that stores encrypted secrets in a local file.

Secrets are hex-encoded ciphertexts stored as JSON. This provider is
intended for single-threaded use only; no file-level locking is implemented.
Concurrent writes from multiple threads or processes will corrupt the file.
"""

from __future__ import annotations

import json
from pathlib import Path

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort


class EncryptedFileSecretProvider(SecretProviderPort):
    def __init__(
        self,
        encryption_service: EncryptionServicePort,
        file_path: str | Path,
    ) -> None:
        self._encryption_service = encryption_service
        self._file_path = Path(file_path)
        self._load()

    def _load(self) -> None:
        if self._file_path.exists():
            raw = self._file_path.read_text(encoding="utf-8")
            self._data: dict[str, str] = json.loads(raw)
        else:
            self._data = {}

    def _save(self) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._file_path.write_text(
            json.dumps(self._data, indent=2),
            encoding="utf-8",
        )

    def get(self, name: str) -> str | None:
        return self._data.get(name)

    def set(self, name: str, value: str) -> None:
        ciphertext = self._encryption_service.encrypt(value)
        self._data[name] = ciphertext.hex()
        self._save()

    def exists(self, name: str) -> bool:
        return name in self._data

    def delete(self, name: str) -> None:
        self._data.pop(name, None)
        self._save()

    def list(self) -> list[str]:
        return list(self._data.keys())
