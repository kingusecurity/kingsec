"""Tests for secret management use cases."""

from __future__ import annotations

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.application.use_cases.decrypt_secret import DecryptSecret
from kingsec.application.use_cases.delete_secret import DeleteSecret
from kingsec.application.use_cases.encrypt_secret import EncryptSecret
from kingsec.application.use_cases.list_secrets import ListSecrets
from kingsec.application.use_cases.retrieve_secret import RetrieveSecret
from kingsec.application.use_cases.rotate_secrets import RotateSecrets
from kingsec.application.use_cases.secret_dto import (
    DecryptSecretRequest,
    DeleteSecretRequest,
    EncryptSecretRequest,
    ListSecretsRequest,
    RetrieveSecretRequest,
    RotateSecretsRequest,
    StoreSecretRequest,
)
from kingsec.application.use_cases.store_secret import StoreSecret
from kingsec.application.use_cases.validate_configuration import (
    ValidateConfiguration,
    ValidateConfigurationRequest,
)


class InMemoryEncryptionService(EncryptionServicePort):
    def __init__(self) -> None:
        self._key = b"test-key-32-bytes-long!!"

    def encrypt(self, plaintext: str) -> bytes:
        return f"ENC({plaintext})".encode()

    def decrypt(self, ciphertext: bytes) -> str:
        raw = ciphertext.decode()
        assert raw.startswith("ENC(") and raw.endswith(")")
        return raw[4:-1]

    def can_decrypt(self, ciphertext: bytes) -> bool:
        return ciphertext.startswith(b"ENC(")


class InMemorySecretProvider(SecretProviderPort):
    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self._secrets.get(name)

    def set(self, name: str, value: str) -> None:
        self._secrets[name] = value

    def exists(self, name: str) -> bool:
        return name in self._secrets

    def delete(self, name: str) -> None:
        self._secrets.pop(name, None)

    def list(self) -> list[str]:
        return list(self._secrets.keys())


class TestEncryptSecret:
    def test_encrypt(self) -> None:
        svc = InMemoryEncryptionService()
        uc = EncryptSecret(svc)
        result = uc.execute(EncryptSecretRequest(plaintext="hello"))
        assert result.ciphertext == b"ENC(hello)"


class TestDecryptSecret:
    def test_decrypt(self) -> None:
        svc = InMemoryEncryptionService()
        uc = DecryptSecret(svc)
        result = uc.execute(DecryptSecretRequest(ciphertext=b"ENC(hello)"))
        assert result.plaintext == "hello"


class TestStoreSecret:
    def test_store_and_metadata(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        uc = StoreSecret(enc, prov)
        result = uc.execute(StoreSecretRequest(name="db_pass", plaintext="s3cret!"))
        assert result.metadata.name == "db_pass"
        assert result.metadata.masked_value == "*******"
        assert prov.exists("db_pass")

    def test_mask_short_value(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        uc = StoreSecret(enc, prov)
        result = uc.execute(StoreSecretRequest(name="short", plaintext="12345678"))
        assert result.metadata.masked_value == "********"

    def test_mask_long_value(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        uc = StoreSecret(enc, prov)
        result = uc.execute(StoreSecretRequest(name="long", plaintext="abcdef1234567890"))
        assert result.metadata.masked_value == "abcd********7890"


class TestRetrieveSecret:
    def test_retrieve_existing(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        store_uc = StoreSecret(enc, prov)
        store_uc.execute(StoreSecretRequest(name="mykey", plaintext="secret_value"))

        retrieve_uc = RetrieveSecret(enc, prov)
        result = retrieve_uc.execute(RetrieveSecretRequest(name="mykey"))
        assert result.plaintext == "secret_value"
        assert result.metadata.name == "mykey"

    def test_retrieve_missing(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        uc = RetrieveSecret(enc, prov)
        try:
            uc.execute(RetrieveSecretRequest(name="nonexistent"))
            assert False, "should raise"
        except Exception:
            pass


class TestDeleteSecret:
    def test_delete_existing(self) -> None:
        prov = InMemorySecretProvider()
        prov.set("mykey", "value")
        uc = DeleteSecret(prov)
        result = uc.execute(DeleteSecretRequest(name="mykey"))
        assert result.success
        assert not prov.exists("mykey")

    def test_delete_missing(self) -> None:
        prov = InMemorySecretProvider()
        uc = DeleteSecret(prov)
        result = uc.execute(DeleteSecretRequest(name="nonexistent"))
        assert not result.success


class TestListSecrets:
    def test_list_empty(self) -> None:
        prov = InMemorySecretProvider()
        uc = ListSecrets(prov)
        result = uc.execute(ListSecretsRequest())
        assert result.secrets == []

    def test_list_with_secrets(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        store_uc = StoreSecret(enc, prov)
        store_uc.execute(StoreSecretRequest(name="key1", plaintext="val1"))
        store_uc.execute(StoreSecretRequest(name="key2", plaintext="val2"))

        list_uc = ListSecrets(prov)
        result = list_uc.execute(ListSecretsRequest())
        assert len(result.secrets) == 2
        names = {s.name for s in result.secrets}
        assert names == {"key1", "key2"}


class TestRotateSecrets:
    def test_rotate_with_no_secrets(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        uc = RotateSecrets(enc, prov)
        result = uc.execute(RotateSecretsRequest())
        assert result.reencrypted_count == 0
        assert len(result.new_key_fingerprint) == 16

    def test_rotate_reencrypts(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        store_uc = StoreSecret(enc, prov)
        store_uc.execute(StoreSecretRequest(name="k1", plaintext="v1"))
        store_uc.execute(StoreSecretRequest(name="k2", plaintext="v2"))

        rotate_uc = RotateSecrets(enc, prov)
        result = rotate_uc.execute(RotateSecretsRequest())
        assert result.reencrypted_count == 2
        assert len(result.new_key_fingerprint) == 16


class TestValidateConfiguration:
    def test_valid(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        prov.set("db_pass", "ENC(value)")
        uc = ValidateConfiguration(enc, prov)
        result = uc.execute(ValidateConfigurationRequest(required_secrets=["db_pass"]))
        assert result.valid
        assert result.missing_secrets == []

    def test_missing_secrets(self) -> None:
        enc = InMemoryEncryptionService()
        prov = InMemorySecretProvider()
        uc = ValidateConfiguration(enc, prov)
        result = uc.execute(ValidateConfigurationRequest(required_secrets=["db_pass", "jwt_key"]))
        assert not result.valid
        assert len(result.missing_secrets) == 2
