"""Secret provider that stores opaque string values in a local file.

This provider does not encrypt or decrypt anything itself - ``get()``/
``set()`` store and return whatever string a caller gives them, verbatim.
Callers (``StoreSecret``, ``RetrieveSecret``, ``RotateSecrets``, etc.) own
encryption entirely: they call ``EncryptionServicePort.encrypt()`` and pass
the resulting hex-encoded ciphertext to ``set()``, and call
``EncryptionServicePort.decrypt()`` on whatever ``get()`` hands back. This
class's own name is a description of what the *file's contents* are
(encrypted), not a claim that this class performs encryption - confusing
the two is exactly what previously caused ``set()`` to encrypt a value
that its only real caller (``StoreSecret``) had already encrypted, and
``RotateSecrets`` to treat undecrypted ciphertext as if it were plaintext.

This provider is intended for single-threaded use only; no file-level
locking is implemented. Concurrent writes from multiple threads or
processes will corrupt the file.
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
        self._data[name] = value
        self._save()

    def exists(self, name: str) -> bool:
        return name in self._data

    def delete(self, name: str) -> None:
        self._data.pop(name, None)
        self._save()

    def list(self) -> list[str]:
        return list(self._data.keys())
