"""Secret provider that reads from environment variables.

Secrets are expected as ``KINGSEC_SECRET__<NAME>`` environment variables.
"""

from __future__ import annotations

import os

from kingsec.application.ports.outbound.secret_provider import SecretProviderPort


class EnvironmentSecretProvider(SecretProviderPort):
    _PREFIX: str = "KINGSEC_SECRET__"

    def get(self, name: str) -> str | None:
        return os.environ.get(f"{self._PREFIX}{name}", None)

    def set(self, name: str, value: str) -> None:
        os.environ[f"{self._PREFIX}{name}"] = value

    def exists(self, name: str) -> bool:
        return f"{self._PREFIX}{name}" in os.environ

    def delete(self, name: str) -> None:
        os.environ.pop(f"{self._PREFIX}{name}", None)

    def list(self) -> list[str]:
        prefix_len = len(self._PREFIX)
        return [
            key[prefix_len:]
            for key in os.environ
            if key.startswith(self._PREFIX)
        ]
