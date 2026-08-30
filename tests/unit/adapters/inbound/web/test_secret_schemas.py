"""Tests for secrets admin API schemas.

Phase 68 / Finding KSEC-64-04: StoreSecretBody.value and .secret_type
previously had no max_length - an admin could submit an arbitrarily
large secret value or type string. The chosen limits are documented in
secret_schemas.py itself (8192 for value, generous margin for real-world
credential formats including PEM-encoded keys/certificates; 64 for
secret_type, generous margin over SecretType's longest defined value).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kingsec.adapters.inbound.web.secret_schemas import StoreSecretBody


class TestStoreSecretBodyValue:
    def test_below_limit_accepted(self) -> None:
        body = StoreSecretBody(name="db-password", value="x" * 8191)
        assert len(body.value) == 8191

    def test_exact_limit_accepted(self) -> None:
        body = StoreSecretBody(name="db-password", value="x" * 8192)
        assert len(body.value) == 8192

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            StoreSecretBody(name="db-password", value="x" * 8193)

    def test_typical_credential_still_accepted(self) -> None:
        body = StoreSecretBody(name="db-password", value="Sup3rSecretPassw0rd!")
        assert body.value == "Sup3rSecretPassw0rd!"

    def test_empty_value_still_rejected(self) -> None:
        """Existing min_length=1 behavior must remain unchanged."""
        with pytest.raises(ValidationError, match="string_too_short"):
            StoreSecretBody(name="db-password", value="")


class TestStoreSecretBodySecretType:
    def test_below_limit_accepted(self) -> None:
        body = StoreSecretBody(name="n", value="v", secret_type="x" * 63)
        assert len(body.secret_type) == 63

    def test_exact_limit_accepted(self) -> None:
        body = StoreSecretBody(name="n", value="v", secret_type="x" * 64)
        assert len(body.secret_type) == 64

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            StoreSecretBody(name="n", value="v", secret_type="x" * 65)

    def test_default_secret_type_still_accepted(self) -> None:
        body = StoreSecretBody(name="n", value="v")
        assert body.secret_type == "database_password"

    def test_real_secret_type_values_still_accepted(self) -> None:
        for secret_type in (
            "database_password",
            "jwt_signing_key",
            "jwt_refresh_key",
            "api_key_pepper",
            "smtp_password",
            "webhook_secret",
            "scanner_credential",
            "ssh_credential",
            "cloud_credential",
        ):
            assert StoreSecretBody(name="n", value="v", secret_type=secret_type).secret_type == secret_type
