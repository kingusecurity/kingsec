"""Tests for secret domain value objects."""

from __future__ import annotations

from kingsec.domain.secret import SecretId, SecretMetadata, SecretType


class TestSecretType:
    def test_values(self) -> None:
        assert SecretType.DATABASE_PASSWORD.value == "database_password"
        assert SecretType.JWT_SIGNING_KEY.value == "jwt_signing_key"
        assert SecretType.JWT_REFRESH_KEY.value == "jwt_refresh_key"
        assert SecretType.API_KEY_PEPPER.value == "api_key_pepper"
        assert SecretType.SMTP_PASSWORD.value == "smtp_password"
        assert SecretType.WEBHOOK_SECRET.value == "webhook_secret"
        assert SecretType.SCANNER_CREDENTIAL.value == "scanner_credential"
        assert SecretType.SSH_CREDENTIAL.value == "ssh_credential"
        assert SecretType.CLOUD_CREDENTIAL.value == "cloud_credential"


class TestSecretId:
    def test_creation(self) -> None:
        sid = SecretId(value="my-secret")
        assert str(sid) == "my-secret"

    def test_frozen(self) -> None:
        sid = SecretId(value="fixed")
        try:
            sid.value = "changed"  # type: ignore[misc]
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestSecretMetadata:
    def test_creation(self) -> None:
        meta = SecretMetadata(
            name="db_password",
            secret_type=SecretType.DATABASE_PASSWORD,
            version=1,
            created_at="2025-01-01T00:00:00+00:00",
            updated_at="2025-01-01T00:00:00+00:00",
            masked_value="****",
        )
        assert meta.name == "db_password"
        assert meta.secret_type == SecretType.DATABASE_PASSWORD
        assert meta.version == 1

    def test_to_dict(self) -> None:
        meta = SecretMetadata(
            name="jwt_key",
            secret_type=SecretType.JWT_SIGNING_KEY,
            version=2,
            created_at="2025-01-01T00:00:00+00:00",
            updated_at="2025-01-02T00:00:00+00:00",
            masked_value="abcd********7890",
        )
        d = meta.to_dict()
        assert d["name"] == "jwt_key"
        assert d["secret_type"] == "jwt_signing_key"
        assert d["version"] == 2
        assert d["masked_value"] == "abcd********7890"

    def test_frozen(self) -> None:
        meta = SecretMetadata(
            name="key",
            secret_type=SecretType.API_KEY_PEPPER,
            version=1,
            created_at="2025-01-01T00:00:00+00:00",
            updated_at="2025-01-01T00:00:00+00:00",
            masked_value="****",
        )
        try:
            meta.name = "changed"  # type: ignore[misc]
            assert False, "should be frozen"
        except AttributeError:
            pass
