"""Tests for MFA domain entities and enums."""
from __future__ import annotations

from kingsec.domain.mfa import MfaRecoveryCode, MfaSecret, MfaStatus, RecoveryCodeStatus


class TestMfaStatus:
    def test_values(self) -> None:
        assert MfaStatus.DISABLED.value == "disabled"
        assert MfaStatus.ENABLED.value == "enabled"


class TestRecoveryCodeStatus:
    def test_values(self) -> None:
        assert RecoveryCodeStatus.ACTIVE.value == "active"
        assert RecoveryCodeStatus.USED.value == "used"


class TestMfaSecret:
    def test_creation(self) -> None:
        secret = MfaSecret(user_id="user-1", secret_key="JBSWY3DPEHPK3PXP", status=MfaStatus.ENABLED)
        assert secret.user_id == "user-1"
        assert secret.secret_key == "JBSWY3DPEHPK3PXP"
        assert secret.status == MfaStatus.ENABLED

    def test_default_status_disabled(self) -> None:
        secret = MfaSecret(user_id="user-1", secret_key="JBSWY3DPEHPK3PXP")
        assert secret.status == MfaStatus.DISABLED

    def test_frozen(self) -> None:
        secret = MfaSecret(user_id="user-1", secret_key="JBSWY3DPEHPK3PXP")
        try:
            secret.user_id = "changed"  # type: ignore[misc]
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestMfaRecoveryCode:
    def test_creation(self) -> None:
        code = MfaRecoveryCode(code_hash="abc123")
        assert code.code_hash == "abc123"
        assert code.status == RecoveryCodeStatus.ACTIVE

    def test_used_status(self) -> None:
        code = MfaRecoveryCode(code_hash="abc123", status=RecoveryCodeStatus.USED)
        assert code.status == RecoveryCodeStatus.USED

    def test_frozen(self) -> None:
        code = MfaRecoveryCode(code_hash="abc123")
        try:
            code.code_hash = "changed"  # type: ignore[misc]
            assert False, "should be frozen"
        except AttributeError:
            pass
