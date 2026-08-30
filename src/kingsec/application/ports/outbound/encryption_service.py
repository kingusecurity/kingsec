"""Port for encryption operations — no infrastructure imports.

There is deliberately no ``rotate_key()`` on this port (Phase 57 / Finding
E-01). A prior design let the encryption service generate a new key for
itself at runtime, holding it only in process memory; since nothing
persisted that key anywhere a future process would read it from, any
restart after such a rotation made every secret re-encrypted under that
key permanently undecryptable. Key material now comes exclusively from
durable, operator-managed configuration (the primary key plus an ordered
list of legacy decrypt-only keys — see ``SecretsSettings`` and
``FernetEncryptionService``), so every key any process can ever encrypt
or decrypt with is one a fresh process reads identically. "Rotation" is
therefore an operator-driven configuration change followed by a restart,
not an in-process operation this port exposes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class EncryptionServicePort(ABC):
    @abstractmethod
    def encrypt(self, plaintext: str) -> bytes: ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> str: ...

    @abstractmethod
    def can_decrypt(self, ciphertext: bytes) -> bool: ...
