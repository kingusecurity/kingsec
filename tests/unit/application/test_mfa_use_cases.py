"""Tests for MFA use cases."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from kingsec.application.errors import ApplicationError
from kingsec.application.ports import PasswordHasher, TokenService
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.application.ports.outbound.totp_service import TotpServicePort
from kingsec.application.use_cases.disable_mfa import DisableMfa
from kingsec.application.use_cases.enable_mfa import EnableMfa
from kingsec.application.use_cases.generate_recovery_codes import GenerateRecoveryCodes
from kingsec.application.use_cases.get_mfa_status import GetMfaStatus
from kingsec.application.use_cases.mfa_dto import (
    DisableMfaRequest,
    EnableMfaRequest,
    GenerateRecoveryCodesRequest,
    RotateRecoveryCodesRequest,
    UseRecoveryCodeRequest,
    VerifyMfaCodeRequest,
)
from kingsec.application.use_cases.rotate_recovery_codes import RotateRecoveryCodes
from kingsec.application.use_cases.use_recovery_code import UseRecoveryCode
from kingsec.application.use_cases.verify_mfa_code import VerifyMfaCode
from kingsec.domain import Role
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
)
from kingsec.domain.mfa import MfaRecoveryCode, MfaSecret, MfaStatus, RecoveryCodeStatus
from kingsec.domain.user import User

# ── Stubs ────────────────────────────────────────────────────────────────────


class StubPasswordHasher(PasswordHasher):
    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify(self, password: str, hash_: str) -> bool:
        return hash_ == f"hashed:{password}"


class StubTokenService(TokenService):
    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        token = f"access:{user_id}"
        self._tokens[token] = user_id
        return token

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        return f"refresh:{user_id}"

    def verify_access_token(self, token: str) -> object:
        return object()

    def verify_refresh_token(self, token: str) -> object:
        return object()

    def revoke_token(self, jti: str) -> None:
        pass

    def is_revoked(self, jti: str) -> bool:
        return False


class StubUserRepo:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def find_by_username(self, username: str) -> User | None:
        for u in self._users.values():
            if u.username.lower() == username.lower():
                return u
        return None

    def find_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def save(self, user: User) -> None:
        self._users[user.id] = user

    def exists_by_username(self, username: str) -> bool:
        return self.find_by_username(username) is not None

    def exists_by_email(self, email: str) -> bool:
        return any(u.email.lower() == email.lower() for u in self._users.values())

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return list(self._users.values())[offset : offset + limit]

    def count(self) -> int:
        return len(self._users)


class StubTotpService(TotpServicePort):
    _VALID_CODE = "123456"

    def generate_secret(self) -> str:
        return "JBSWY3DPEHPK3PXP"

    def generate_uri(self, secret: str, username: str, issuer: str = "KingSec") -> str:
        return f"otpauth://totp/{issuer}:{username}?secret={secret}"

    def verify(self, secret: str, code: str, drift: int = 1) -> bool:
        return code == self._VALID_CODE


class StubMfaSecretRepo(MfaSecretRepository):
    def __init__(self) -> None:
        self._secrets: dict[str, MfaSecret] = {}

    def find_by_user_id(self, user_id: str) -> MfaSecret | None:
        return self._secrets.get(user_id)

    def save(self, secret: MfaSecret) -> None:
        self._secrets[secret.user_id] = secret

    def delete_by_user_id(self, user_id: str) -> None:
        self._secrets.pop(user_id, None)


class StubRecoveryCodeRepo(RecoveryCodeRepository):
    def __init__(self) -> None:
        self._codes: dict[str, list[MfaRecoveryCode]] = {}

    def find_by_user_id(self, user_id: str) -> Sequence[MfaRecoveryCode]:
        return self._codes.get(user_id, [])

    def save_batch(self, user_id: str, codes: Sequence[MfaRecoveryCode]) -> None:
        self._codes[user_id] = list(codes)

    def mark_used(self, user_id: str, code_hash: str) -> None:
        codes = self._codes.get(user_id, [])
        for c in codes:
            if c.code_hash == code_hash:
                self._codes[user_id] = [
                    MfaRecoveryCode(code_hash=c.code_hash, status=RecoveryCodeStatus.USED) if i == codes.index(c) else c
                    for i, c in enumerate(codes)
                ]
                return

    def delete_by_user_id(self, user_id: str) -> None:
        self._codes.pop(user_id, None)


class StubAuditRepo(AuditEventRepository):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def save(self, event: AuditEvent) -> None:
        self.events.append(event)

    def find_by_id(self, event_id: AuditEventId) -> AuditEvent | None:
        return None

    def search(self, **kwargs) -> tuple[list[AuditEvent], int]:
        return [], 0


# ── Tests ────────────────────────────────────────────────────────────────────


class TestGetMfaStatus:
    def test_disabled_when_no_secret(self) -> None:
        repo = StubMfaSecretRepo()
        uc = GetMfaStatus(repo)
        result = uc.execute("user-1")
        assert result.enabled is False

    def test_enabled(self) -> None:
        repo = StubMfaSecretRepo()
        repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))
        uc = GetMfaStatus(repo)
        result = uc.execute("user-1")
        assert result.enabled is True


class TestEnableMfa:
    def test_enable_creates_secret(self) -> None:
        secret_repo = StubMfaSecretRepo()
        totp = StubTotpService()
        audit = StubAuditRepo()
        uc = EnableMfa(secret_repo, totp, audit)

        result = uc.execute(EnableMfaRequest(user_id="user-1"))

        assert result.secret == "JBSWY3DPEHPK3PXP"
        assert "otpauth://" in result.uri
        secret = secret_repo.find_by_user_id("user-1")
        assert secret is not None
        assert secret.status == MfaStatus.ENABLED

    def test_enable_creates_audit_event(self) -> None:
        secret_repo = StubMfaSecretRepo()
        totp = StubTotpService()
        audit = StubAuditRepo()
        uc = EnableMfa(secret_repo, totp, audit)

        uc.execute(EnableMfaRequest(user_id="user-1"))
        assert len(audit.events) == 1
        assert audit.events[0].action == AuditAction.PASSWORD_CHANGED


class TestDisableMfa:
    def test_disable_removes_secret(self) -> None:
        secret_repo = StubMfaSecretRepo()
        recovery_repo = StubRecoveryCodeRepo()
        audit = StubAuditRepo()
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))

        uc = DisableMfa(secret_repo, recovery_repo, audit)
        uc.execute(DisableMfaRequest(user_id="user-1"))

        assert secret_repo.find_by_user_id("user-1") is None

    def test_disable_creates_audit_event(self) -> None:
        secret_repo = StubMfaSecretRepo()
        recovery_repo = StubRecoveryCodeRepo()
        audit = StubAuditRepo()
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))

        uc = DisableMfa(secret_repo, recovery_repo, audit)
        uc.execute(DisableMfaRequest(user_id="user-1"))

        assert len(audit.events) == 1
        assert audit.events[0].action == AuditAction.PASSWORD_CHANGED


class TestVerifyMfaCode:
    def _setup(self) -> tuple[VerifyMfaCode, StubUserRepo, StubMfaSecretRepo]:
        users = StubUserRepo()
        hasher = StubPasswordHasher()
        tokens = StubTokenService()
        secret_repo = StubMfaSecretRepo()
        totp = StubTotpService()

        user = User(
            id="user-1",
            username="testuser",
            email="test@example.com",
            password_hash=hasher.hash("pass123"),
            role=Role.VIEWER,
        )
        users.save(user)
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="JBSWY3DPEHPK3PXP", status=MfaStatus.ENABLED))

        uc = VerifyMfaCode(users, hasher, tokens, secret_repo, totp)
        return uc, users, secret_repo

    def test_valid_code_returns_tokens(self) -> None:
        uc, _, _ = self._setup()
        result = uc.execute(VerifyMfaCodeRequest(username="testuser", password="pass123", totp_code="123456"))
        assert result.access_token == "access:user-1"
        assert result.username == "testuser"

    def test_invalid_password_raises_error(self) -> None:
        uc, _, _ = self._setup()
        with pytest.raises(ApplicationError, match="invalid username or password"):
            uc.execute(VerifyMfaCodeRequest(username="testuser", password="wrong", totp_code="123456"))

    def test_invalid_totp_raises_error(self) -> None:
        uc, _, _ = self._setup()
        with pytest.raises(ApplicationError, match="invalid TOTP code"):
            uc.execute(VerifyMfaCodeRequest(username="testuser", password="pass123", totp_code="999999"))

    def test_unknown_user_raises_error(self) -> None:
        uc, _, _ = self._setup()
        with pytest.raises(ApplicationError, match="invalid username or password"):
            uc.execute(VerifyMfaCodeRequest(username="nobody", password="pass123", totp_code="123456"))

    def test_mfa_not_enabled_raises_error(self) -> None:
        users = StubUserRepo()
        hasher = StubPasswordHasher()
        tokens = StubTokenService()
        secret_repo = StubMfaSecretRepo()
        totp = StubTotpService()

        user = User(
            id="user-2",
            username="nomfa",
            email="nomfa@example.com",
            password_hash=hasher.hash("pass"),
            role=Role.VIEWER,
        )
        users.save(user)

        uc = VerifyMfaCode(users, hasher, tokens, secret_repo, totp)
        with pytest.raises(ApplicationError, match="MFA is not enabled"):
            uc.execute(VerifyMfaCodeRequest(username="nomfa", password="pass", totp_code="123456"))


class TestGenerateRecoveryCodes:
    def test_generates_ten_codes(self) -> None:
        repo = StubRecoveryCodeRepo()
        uc = GenerateRecoveryCodes(repo)
        result = uc.execute(GenerateRecoveryCodesRequest(user_id="user-1"))
        assert len(result.codes) == 10

    def test_codes_are_stored_hashed(self) -> None:
        import hashlib

        repo = StubRecoveryCodeRepo()
        uc = GenerateRecoveryCodes(repo)
        result = uc.execute(GenerateRecoveryCodesRequest(user_id="user-1"))

        stored = repo.find_by_user_id("user-1")
        assert len(stored) == 10
        for plaintext, stored_code in zip(result.codes, stored, strict=False):
            expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()
            assert stored_code.code_hash == expected_hash
            assert stored_code.status == RecoveryCodeStatus.ACTIVE


class TestUseRecoveryCode:
    def test_valid_recovery_code_returns_tokens(self) -> None:
        users = StubUserRepo()
        hasher = StubPasswordHasher()
        tokens = StubTokenService()
        secret_repo = StubMfaSecretRepo()
        recovery_repo = StubRecoveryCodeRepo()

        user = User(
            id="user-1",
            username="testuser",
            email="test@example.com",
            password_hash=hasher.hash("pass"),
            role=Role.ADMIN,
        )
        users.save(user)
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))

        uc_gen = GenerateRecoveryCodes(recovery_repo)
        gen_result = uc_gen.execute(GenerateRecoveryCodesRequest(user_id="user-1"))

        uc_use = UseRecoveryCode(users, hasher, tokens, secret_repo, recovery_repo)
        result = uc_use.execute(
            UseRecoveryCodeRequest(username="testuser", password="pass", recovery_code=gen_result.codes[0])
        )
        assert result.access_token == "access:user-1"

    def test_used_code_cannot_be_reused(self) -> None:
        users = StubUserRepo()
        hasher = StubPasswordHasher()
        tokens = StubTokenService()
        secret_repo = StubMfaSecretRepo()
        recovery_repo = StubRecoveryCodeRepo()

        user = User(
            id="user-1",
            username="testuser",
            email="test@example.com",
            password_hash=hasher.hash("pass"),
            role=Role.ADMIN,
        )
        users.save(user)
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))

        uc_gen = GenerateRecoveryCodes(recovery_repo)
        gen_result = uc_gen.execute(GenerateRecoveryCodesRequest(user_id="user-1"))

        uc_use = UseRecoveryCode(users, hasher, tokens, secret_repo, recovery_repo)
        uc_use.execute(UseRecoveryCodeRequest(username="testuser", password="pass", recovery_code=gen_result.codes[0]))

        with pytest.raises(ApplicationError, match="invalid recovery code"):
            uc_use.execute(
                UseRecoveryCodeRequest(username="testuser", password="pass", recovery_code=gen_result.codes[0])
            )

    def test_invalid_password_raises_error(self) -> None:
        users = StubUserRepo()
        hasher = StubPasswordHasher()
        tokens = StubTokenService()
        secret_repo = StubMfaSecretRepo()
        recovery_repo = StubRecoveryCodeRepo()

        user = User(
            id="user-1",
            username="testuser",
            email="test@example.com",
            password_hash=hasher.hash("pass"),
            role=Role.ADMIN,
        )
        users.save(user)
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))

        uc_use = UseRecoveryCode(users, hasher, tokens, secret_repo, recovery_repo)
        with pytest.raises(ApplicationError, match="invalid username or password"):
            uc_use.execute(UseRecoveryCodeRequest(username="testuser", password="wrong", recovery_code="some-code"))


class TestRotateRecoveryCodes:
    def test_rotates_all_codes(self) -> None:

        repo = StubRecoveryCodeRepo()
        audit = StubAuditRepo()

        initial = GenerateRecoveryCodes(repo)
        initial.execute(GenerateRecoveryCodesRequest(user_id="user-1"))

        first_batch = repo.find_by_user_id("user-1")
        first_hashes = [c.code_hash for c in first_batch]

        uc = RotateRecoveryCodes(repo, audit)
        result = uc.execute(RotateRecoveryCodesRequest(user_id="user-1"))

        assert len(result.codes) == 10
        rotated_batch = repo.find_by_user_id("user-1")
        rotated_hashes = [c.code_hash for c in rotated_batch]

        # All new hashes should be different from old ones
        for h in rotated_hashes:
            assert h not in first_hashes

    def test_rotate_creates_audit_event(self) -> None:
        repo = StubRecoveryCodeRepo()
        audit = StubAuditRepo()

        uc = RotateRecoveryCodes(repo, audit)
        uc.execute(RotateRecoveryCodesRequest(user_id="user-1"))

        assert len(audit.events) == 1
        assert audit.events[0].action == AuditAction.PASSWORD_CHANGED
