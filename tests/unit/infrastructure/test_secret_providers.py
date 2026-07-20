"""Tests for EnvironmentSecretProvider and EncryptedFileSecretProvider."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

from kingsec.infrastructure.secrets.encrypted_file_secret_provider import (
    EncryptedFileSecretProvider,
)
from kingsec.infrastructure.secrets.environment_secret_provider import (
    EnvironmentSecretProvider,
)
from kingsec.infrastructure.secrets.fernet_encryption_service import (
    FernetEncryptionService,
)


class TestEnvironmentSecretProvider:
    def setup_method(self) -> None:
        self._prefix = "KINGSEC_SECRET__"
        self._cleanup_keys: list[str] = []

    def teardown_method(self) -> None:
        for key in self._cleanup_keys:
            os.environ.pop(key, None)

    def _set(self, name: str, value: str) -> None:
        key = f"{self._prefix}{name}"
        os.environ[key] = value
        self._cleanup_keys.append(key)

    def test_get_set_exists(self) -> None:
        prov = EnvironmentSecretProvider()
        self._set("TEST_KEY", "test_value")
        assert prov.get("TEST_KEY") == "test_value"
        assert prov.exists("TEST_KEY")

    def test_get_missing(self) -> None:
        prov = EnvironmentSecretProvider()
        assert prov.get("NONEXISTENT") is None

    def test_delete(self) -> None:
        prov = EnvironmentSecretProvider()
        self._set("DELETE_KEY", "value")
        assert prov.exists("DELETE_KEY")
        prov.delete("DELETE_KEY")
        assert not prov.exists("DELETE_KEY")

    def test_list(self) -> None:
        prov = EnvironmentSecretProvider()
        self._set("LIST_A", "a")
        self._set("LIST_B", "b")
        names = prov.list()
        assert "LIST_A" in names
        assert "LIST_B" in names


class TestEncryptedFileSecretProvider:
    def test_round_trip(self) -> None:
        key = Fernet.generate_key()
        enc = FernetEncryptionService(key=key)
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write("{}")
            path = Path(f.name)

        try:
            prov = EncryptedFileSecretProvider(enc, str(path))
            prov.set("db_pass", "s3cret!")
            assert prov.exists("db_pass")
            assert prov.get("db_pass") is not None
            names = prov.list()
            assert "db_pass" in names
        finally:
            path.unlink(missing_ok=True)
            path.with_suffix(".lock").unlink(missing_ok=True)

    def test_delete(self) -> None:
        key = Fernet.generate_key()
        enc = FernetEncryptionService(key=key)
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write("{}")
            path = Path(f.name)

        try:
            prov = EncryptedFileSecretProvider(enc, str(path))
            prov.set("k1", "v1")
            assert prov.exists("k1")
            prov.delete("k1")
            assert not prov.exists("k1")
        finally:
            path.unlink(missing_ok=True)
            path.with_suffix(".lock").unlink(missing_ok=True)

    def test_list_empty(self) -> None:
        key = Fernet.generate_key()
        enc = FernetEncryptionService(key=key)
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write("{}")
            path = Path(f.name)

        try:
            prov = EncryptedFileSecretProvider(enc, str(path))
            assert prov.list() == []
        finally:
            path.unlink(missing_ok=True)
            path.with_suffix(".lock").unlink(missing_ok=True)
