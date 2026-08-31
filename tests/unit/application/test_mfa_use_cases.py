"""Tests for MFA use cases."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from kingsec.application.errors import ApplicationError
from kingsec.application.ports import PasswordHasher, TokenClaims, TokenService
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.application.ports.outbound.token_service import TokenInvalidError
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
    """Fake that actually round-trips pending tokens, so VerifyMfaCode/
    UseRecoveryCode can be tested against realistic verify() behavior
    (unknown/revoked/wrong-type tokens genuinely rejected) rather than a
    token that always successfully decodes to whatever the test wants."""

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}
        self._pending: dict[str, TokenClaims] = {}
        self._revoked: set[str] = set()
        self.pending_tokens_issued = 0

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        token = f"access:{user_id}"
        self._tokens[token] = user_id
        return token

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        return f"refresh:{user_id}"

    def create_mfa_pending_token(self, user_id: str, username: str, role: str) -> str:
        self.pending_tokens_issued += 1
        jti = f"pending-jti-{self.pending_tokens_issued}"
        token = f"pending:{jti}"
        self._pending[token] = TokenClaims(
            user_id=user_id,
            username=username,
            role=role,
            token_type="mfa_pending",
            jti=jti,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )
        return token

    def verify_access_token(self, token: str) -> object:
        return object()

    def verify_refresh_token(self, token: str) -> object:
        return object()

    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        claims = self._pending.get(token)
        if claims is None:
            raise TokenInvalidError("invalid pending token")
        if claims.jti in self._revoked:
            raise TokenInvalidError("token has been revoked")
        return claims

    def revoke_token(self, jti: str) -> None:
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked


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

    def mark_used(self, user_id: str, code_hash: str) -> bool:
        codes = self._codes.get(user_id, [])
        for i, c in enumerate(codes):
            if c.code_hash == code_hash:
                if c.status == RecoveryCodeStatus.USED:
                    return False
                codes[i] = MfaRecoveryCode(code_hash=c.code_hash, status=RecoveryCodeStatus.USED)
                return True
        return False

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
    def _setup(self) -> tuple[DisableMfa, StubMfaSecretRepo, StubRecoveryCodeRepo, StubAuditRepo]:
        secret_repo = StubMfaSecretRepo()
        recovery_repo = StubRecoveryCodeRepo()
        users = StubUserRepo()
        hasher = StubPasswordHasher()
        audit = StubAuditRepo()
        secret_repo.save(MfaSecret(user_id="user-1", secret_key="secret", status=MfaStatus.ENABLED))
        recovery_repo.save_batch(
            "user-1", [MfaRecoveryCode(code_hash="hash-1", status=RecoveryCodeStatus.ACTIVE)]
        )
        users.save(
            User(
                id="user-1",
                username="testuser",
                email="test@example.com",
                password_hash=hasher.hash("pass123"),
                role=Role.VIEWER,
            )
        )
        uc = DisableMfa(secret_repo, recovery_repo, users, hasher, audit)
        return uc, secret_repo, recovery_repo, audit

    def test_disable_removes_secret(self) -> None:
        uc, secret_repo, _recovery_repo, _audit = self._setup()
        uc.execute(DisableMfaRequest(user_id="user-1", current_password="pass123"))

        assert secret_repo.find_by_user_id("user-1") is None

    def test_disable_creates_audit_event(self) -> None:
        uc, _secret_repo, _recovery_repo, audit = self._setup()
        uc.execute(DisableMfaRequest(user_id="user-1", current_password="pass123"))

        assert len(audit.events) == 1
        assert audit.events[0].action == AuditAction.PASSWORD_CHANGED

    def test_disable_without_step_up_password_is_rejected(self) -> None:
        """KSEC-73-03: no current_password supplied -> rejected, MFA and
        recovery codes remain intact."""
        uc, secret_repo, recovery_repo, audit = self._setup()
        with pytest.raises(ApplicationError, match="current password is incorrect"):
            uc.execute(DisableMfaRequest(user_id="user-1", current_password=""))

        assert secret_repo.find_by_user_id("user-1") is not None
        assert len(recovery_repo.find_by_user_id("user-1")) == 1
        assert audit.events == []

    def test_disable_with_incorrect_step_up_password_is_rejected(self) -> None:
        """KSEC-73-03: a valid access token alone (represented here by a
        bare user_id) must not be sufficient - a wrong password is
        rejected exactly like a missing one."""
        uc, secret_repo, recovery_repo, audit = self._setup()
        with pytest.raises(ApplicationError, match="current password is incorrect"):
            uc.execute(DisableMfaRequest(user_id="user-1", current_password="totally-wrong"))

        assert secret_repo.find_by_user_id("user-1") is not None
        assert len(recovery_repo.find_by_user_id("user-1")) == 1
        assert audit.events == []

    def test_disable_by_admin_skips_step_up(self) -> None:
        """The distinct admin route (already require_admin_jwt_only-gated)
        cannot know the target's password - is_admin=True bypasses the
        self-service step-up check without weakening it."""
        uc, secret_repo, _recovery_repo, _audit = self._setup()
        uc.execute(DisableMfaRequest(user_id="user-1", is_admin=True))

        assert secret_repo.find_by_user_id("user-1") is None


class TestVerifyMfaCode:
    def _setup(self) -> tuple[VerifyMfaCode, StubUserRepo, StubMfaSecretRepo, StubTokenService, str]:
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

        # Simulates what Login does once password/lockout/active checks pass.
        pending_token = tokens.create_mfa_pending_token(user_id="user-1", username="testuser", role="Viewer")

        uc = VerifyMfaCode(users, tokens, secret_repo, totp)
        return uc, users, secret_repo, tokens, pending_token

    def test_valid_code_returns_tokens(self) -> None:
        uc, _, _, _, pending_token = self._setup()
        result = uc.execute(VerifyMfaCodeRequest(pending_token=pending_token, totp_code="123456"))
        assert result.access_token == "access:user-1"
        assert result.username == "testuser"

    def test_invalid_pending_token_raises_error(self) -> None:
        uc, _, _, _, _ = self._setup()
        with pytest.raises(ApplicationError, match="invalid or expired login attempt"):
            uc.execute(VerifyMfaCodeRequest(pending_token="not-a-real-token", totp_code="123456"))

    def test_invalid_totp_raises_error(self) -> None:
        uc, _, _, _, pending_token = self._setup()
        with pytest.raises(ApplicationError, match="invalid TOTP code"):
            uc.execute(VerifyMfaCodeRequest(pending_token=pending_token, totp_code="999999"))

    def test_pending_token_cannot_be_reused_after_success(self) -> None:
        """Single-use: once a pending token completes a login, it must be
        rejected on any further attempt, even within its validity window."""
        uc, _, _, _, pending_token = self._setup()
        uc.execute(VerifyMfaCodeRequest(pending_token=pending_token, totp_code="123456"))

        with pytest.raises(ApplicationError, match="invalid or expired login attempt"):
            uc.execute(VerifyMfaCodeRequest(pending_token=pending_token, totp_code="123456"))

    def test_pending_token_only_completes_its_own_user(self) -> None:
        """A pending token minted for one user cannot be used to complete a
        login as a different user - there is no username in this request at
        all, so the token itself is the only identity source."""
        uc, users, secret_repo, tokens, _ = self._setup()
        other = User(
            id="user-other",
            username="otheruser",
            email="other@example.com",
            password_hash="irrelevant",
            role=Role.VIEWER,
        )
        users.save(other)
        secret_repo.save(MfaSecret(user_id="user-other", secret_key="ANYSECRET", status=MfaStatus.ENABLED))
        other_pending = tokens.create_mfa_pending_token(user_id="user-other", username="otheruser", role="Viewer")

        result = uc.execute(VerifyMfaCodeRequest(pending_token=other_pending, totp_code="123456"))
        assert result.user_id == "user-other"
        assert result.username == "otheruser"

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
        pending_token = tokens.create_mfa_pending_token(user_id="user-2", username="nomfa", role="Viewer")

        uc = VerifyMfaCode(users, tokens, secret_repo, totp)
        with pytest.raises(ApplicationError, match="MFA is not enabled"):
            uc.execute(VerifyMfaCodeRequest(pending_token=pending_token, totp_code="123456"))


def _make_user_repo_with_password(user_id: str, password: str, hasher: StubPasswordHasher) -> StubUserRepo:
    users = StubUserRepo()
    users.save(
        User(
            id=user_id,
            username="testuser",
            email="test@example.com",
            password_hash=hasher.hash(password),
            role=Role.VIEWER,
        )
    )
    return users


class TestGenerateRecoveryCodes:
    def test_generates_ten_codes(self) -> None:
        repo = StubRecoveryCodeRepo()
        hasher = StubPasswordHasher()
        users = _make_user_repo_with_password("user-1", "pass123", hasher)
        uc = GenerateRecoveryCodes(repo, users, hasher)
        result = uc.execute(GenerateRecoveryCodesRequest(user_id="user-1", current_password="pass123"))
        assert len(result.codes) == 10

    def test_codes_are_stored_hashed(self) -> None:
        import hashlib

        repo = StubRecoveryCodeRepo()
        hasher = StubPasswordHasher()
        users = _make_user_repo_with_password("user-1", "pass123", hasher)
        uc = GenerateRecoveryCodes(repo, users, hasher)
        result = uc.execute(GenerateRecoveryCodesRequest(user_id="user-1", current_password="pass123"))

        stored = repo.find_by_user_id("user-1")
        assert len(stored) == 10
        for plaintext, stored_code in zip(result.codes, stored, strict=False):
            expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()
            assert stored_code.code_hash == expected_hash
            assert stored_code.status == RecoveryCodeStatus.ACTIVE

    def test_generate_without_step_up_password_is_rejected(self) -> None:
        repo = StubRecoveryCodeRepo()
        hasher = StubPasswordHasher()
        users = _make_user_repo_with_password("user-1", "pass123", hasher)
        uc = GenerateRecoveryCodes(repo, users, hasher)
        with pytest.raises(ApplicationError, match="current password is incorrect"):
            uc.execute(GenerateRecoveryCodesRequest(user_id="user-1", current_password="wrong"))

        assert repo.find_by_user_id("user-1") == []


def _seed_recovery_codes(repo: StubRecoveryCodeRepo, user_id: str, plaintext_codes: list[str]) -> None:
    """Seed a recovery-code repo directly, bypassing GenerateRecoveryCodes'
    own step-up requirement - irrelevant to tests that exercise recovery
    CODE USAGE (UseRecoveryCode), not code generation."""
    import hashlib

    repo.save_batch(
        user_id,
        [
            MfaRecoveryCode(code_hash=hashlib.sha256(c.encode()).hexdigest(), status=RecoveryCodeStatus.ACTIVE)
            for c in plaintext_codes
        ],
    )


class TestUseRecoveryCode:
    def _setup(self) -> tuple[UseRecoveryCode, StubTokenService, StubRecoveryCodeRepo, str]:
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
        pending_token = tokens.create_mfa_pending_token(user_id="user-1", username="testuser", role="Admin")

        uc = UseRecoveryCode(users, tokens, secret_repo, recovery_repo)
        return uc, tokens, recovery_repo, pending_token

    def test_valid_recovery_code_returns_tokens(self) -> None:
        uc, _tokens, recovery_repo, pending_token = self._setup()
        codes = ["code-a", "code-b"]
        _seed_recovery_codes(recovery_repo, "user-1", codes)

        result = uc.execute(UseRecoveryCodeRequest(pending_token=pending_token, recovery_code=codes[0]))
        assert result.access_token == "access:user-1"

    def test_used_code_cannot_be_reused(self) -> None:
        uc, tokens, recovery_repo, pending_token = self._setup()
        codes = ["code-a", "code-b"]
        _seed_recovery_codes(recovery_repo, "user-1", codes)

        uc.execute(UseRecoveryCodeRequest(pending_token=pending_token, recovery_code=codes[0]))

        # A second pending token, since the first was consumed (single-use)
        # by the successful completion above - isolates "code already used"
        # from "pending token already used", tested separately below.
        second_pending = tokens.create_mfa_pending_token(user_id="user-1", username="testuser", role="Admin")
        with pytest.raises(ApplicationError, match="invalid recovery code"):
            uc.execute(UseRecoveryCodeRequest(pending_token=second_pending, recovery_code=codes[0]))

    def test_pending_token_cannot_be_reused_after_success(self) -> None:
        uc, _, recovery_repo, pending_token = self._setup()
        codes = ["code-a", "code-b"]
        _seed_recovery_codes(recovery_repo, "user-1", codes)

        uc.execute(UseRecoveryCodeRequest(pending_token=pending_token, recovery_code=codes[0]))

        with pytest.raises(ApplicationError, match="invalid or expired login attempt"):
            uc.execute(UseRecoveryCodeRequest(pending_token=pending_token, recovery_code=codes[1]))

    def test_invalid_pending_token_raises_error(self) -> None:
        uc, _, _, _ = self._setup()
        with pytest.raises(ApplicationError, match="invalid or expired login attempt"):
            uc.execute(UseRecoveryCodeRequest(pending_token="not-a-real-token", recovery_code="some-code"))


class TestRotateRecoveryCodes:
    def _setup(self) -> tuple[RotateRecoveryCodes, StubRecoveryCodeRepo, StubUserRepo, StubPasswordHasher, StubAuditRepo]:
        repo = StubRecoveryCodeRepo()
        hasher = StubPasswordHasher()
        users = _make_user_repo_with_password("user-1", "pass123", hasher)
        audit = StubAuditRepo()
        uc = RotateRecoveryCodes(repo, users, hasher, audit)
        return uc, repo, users, hasher, audit

    def test_rotates_all_codes(self) -> None:
        uc, repo, _users, _hasher, _audit = self._setup()
        _seed_recovery_codes(repo, "user-1", ["old-code-0", "old-code-1"])
        first_batch = repo.find_by_user_id("user-1")
        first_hashes = [c.code_hash for c in first_batch]

        result = uc.execute(RotateRecoveryCodesRequest(user_id="user-1", current_password="pass123"))

        assert len(result.codes) == 10
        rotated_batch = repo.find_by_user_id("user-1")
        rotated_hashes = [c.code_hash for c in rotated_batch]

        # All new hashes should be different from old ones
        for h in rotated_hashes:
            assert h not in first_hashes

    def test_rotate_creates_audit_event(self) -> None:
        uc, _repo, _users, _hasher, audit = self._setup()
        uc.execute(RotateRecoveryCodesRequest(user_id="user-1", current_password="pass123"))

        assert len(audit.events) == 1
        assert audit.events[0].action == AuditAction.PASSWORD_CHANGED

    def test_rotate_without_step_up_password_is_rejected(self) -> None:
        uc, repo, _users, _hasher, audit = self._setup()
        _seed_recovery_codes(repo, "user-1", ["old-code-0"])
        original = [c.code_hash for c in repo.find_by_user_id("user-1")]

        with pytest.raises(ApplicationError, match="current password is incorrect"):
            uc.execute(RotateRecoveryCodesRequest(user_id="user-1", current_password="wrong"))

        # Existing codes are untouched by the rejected attempt.
        assert [c.code_hash for c in repo.find_by_user_id("user-1")] == original
        assert audit.events == []
