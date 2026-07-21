"""Integration test: MFA (TOTP) endpoints.

Verifies:
1. GET /api/v1/mfa/status returns disabled by default
2. POST /api/v1/mfa/enable returns secret and URI
3. POST /api/v1/mfa/verify authenticates with valid TOTP
4. POST /api/v1/mfa/verify rejects invalid TOTP
5. POST /api/v1/mfa/disable disables MFA
6. POST /api/v1/mfa/recovery authenticates with recovery code
7. POST /api/v1/mfa/recovery/rotate replaces codes
8. GET /api/v1/mfa/status returns enabled after enable
9. POST /api/v1/mfa/verify rejects when MFA not enabled
10. Unauthenticated requests return 401
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import PasswordHasher, TokenService
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.application.ports.outbound.totp_service import TotpServicePort
from kingsec.application.use_cases.disable_mfa import DisableMfa
from kingsec.application.use_cases.enable_mfa import EnableMfa
from kingsec.application.use_cases.generate_recovery_codes import GenerateRecoveryCodes
from kingsec.application.use_cases.get_mfa_status import GetMfaStatus
from kingsec.application.use_cases.rotate_recovery_codes import RotateRecoveryCodes
from kingsec.application.use_cases.use_recovery_code import UseRecoveryCode
from kingsec.application.use_cases.verify_mfa_code import VerifyMfaCode
from kingsec.domain.mfa import MfaRecoveryCode, MfaSecret, RecoveryCodeStatus

from .test_audit_events_integration import StubAuditEventRepository as EventRepo
from .test_auth_integration import StubHasher, StubTokenService, StubUserRepo


class StubTotpService(TotpServicePort):
    _VALID = "123456"

    def generate_secret(self) -> str:
        return "JBSWY3DPEHPK3PXP"

    def generate_uri(self, secret: str, username: str, issuer: str = "KingSec") -> str:
        return f"otpauth://totp/{issuer}:{username}?secret={secret}"

    def verify(self, secret: str, code: str, drift: int = 1) -> bool:
        return code == self._VALID


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

    def find_by_user_id(self, user_id: str) -> list[MfaRecoveryCode]:
        return self._codes.get(user_id, [])

    def save_batch(self, user_id: str, codes: list[MfaRecoveryCode]) -> None:
        self._codes[user_id] = list(codes)

    def mark_used(self, user_id: str, code_hash: str) -> None:
        codes = self._codes.get(user_id, [])
        for i, c in enumerate(codes):
            if c.code_hash == code_hash:
                codes[i] = MfaRecoveryCode(code_hash=c.code_hash, status=RecoveryCodeStatus.USED)
                break

    def delete_by_user_id(self, user_id: str) -> None:
        self._codes.pop(user_id, None)


def _build_app() -> tuple[FastAPI, StubUserRepo, StubTokenService, StubMfaSecretRepo, StubRecoveryCodeRepo, EventRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    mfa_secret_repo = StubMfaSecretRepo()
    recovery_repo = StubRecoveryCodeRepo()
    totp_service = StubTotpService()
    audit_repo = EventRepo()

    app = FastAPI()

    class _StubApp:
        def resolve(self, service_type: type):
            from kingsec.application import Login, RefreshToken, RegisterUser
            from kingsec.application.ports import UserRepository

            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == PasswordHasher:
                return hasher
            if service_type == RegisterUser:
                return RegisterUser(user_repo, hasher)
            if service_type == Login:
                return Login(user_repo, hasher, token_service)
            if service_type == RefreshToken:
                return RefreshToken(user_repo, token_service)
            if service_type == MfaSecretRepository:
                return mfa_secret_repo
            if service_type == RecoveryCodeRepository:
                return recovery_repo
            if service_type == TotpServicePort:
                return totp_service
            if service_type == AuditEventRepository:
                return audit_repo
            if service_type == GetMfaStatus:
                return GetMfaStatus(mfa_secret_repo)
            if service_type == EnableMfa:
                return EnableMfa(mfa_secret_repo, totp_service, audit_repo)
            if service_type == DisableMfa:
                return DisableMfa(mfa_secret_repo, recovery_repo, audit_repo)
            if service_type == VerifyMfaCode:
                return VerifyMfaCode(user_repo, hasher, token_service, mfa_secret_repo, totp_service, None, audit_repo)
            if service_type == GenerateRecoveryCodes:
                return GenerateRecoveryCodes(recovery_repo)
            if service_type == UseRecoveryCode:
                return UseRecoveryCode(user_repo, hasher, token_service, mfa_secret_repo, recovery_repo, None, audit_repo)
            if service_type == RotateRecoveryCodes:
                return RotateRecoveryCodes(recovery_repo, audit_repo)
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.mfa_routes import router as mfa_router
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.include_router(mfa_router)

    return app, user_repo, token_service, mfa_secret_repo, recovery_repo, audit_repo


def _register_and_login(client: TestClient, username: str = "testuser", role: str = "ADMIN") -> str:
    resp = client.post("/api/v1/auth/register", json={"username": username, "email": f"{username}@example.com", "password": "Passw0rd!", "role": role})
    assert resp.status_code in (200, 201)
    login_resp = client.post("/api/v1/auth/login", json={"username": username, "password": "Passw0rd!"})
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


class TestMfaIntegration:
    def test_status_disabled_by_default(self) -> None:
        app, _, _token_service, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        token = _register_and_login(client, username="user1")
        resp = client.get("/api/v1/mfa/status", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    def test_enable_returns_secret_and_uri(self) -> None:
        app, _, _token_service, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        token = _register_and_login(client, username="user2")
        resp = client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert "uri" in data
        assert data["secret"] == "JBSWY3DPEHPK3PXP"
        assert "otpauth://" in data["uri"]

    def test_status_enabled_after_enable(self) -> None:
        app, _, _token_service, _mfa_repo, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        token = _register_and_login(client, username="user3")

        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})
        resp = client.get("/api/v1/mfa/status", headers={"Authorization": f"Bearer {token}"})
        assert resp.json()["enabled"] is True

    def test_verify_valid_totp(self) -> None:
        app, _, _token_service, _mfa_repo, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user4")

        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})

        resp = client.post("/api/v1/mfa/verify", json={"username": "user4", "password": "Passw0rd!", "totp_code": "123456"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["username"] == "user4"

    def test_verify_invalid_totp(self) -> None:
        app, _, _token_service, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user5")
        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})

        resp = client.post("/api/v1/mfa/verify", json={"username": "user5", "password": "Passw0rd!", "totp_code": "999999"})
        assert resp.status_code == 401

    def test_verify_wrong_password(self) -> None:
        app, _, _token_service, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user6")
        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})

        resp = client.post("/api/v1/mfa/verify", json={"username": "user6", "password": "wrongpass", "totp_code": "123456"})
        assert resp.status_code == 401

    def test_disable_mfa(self) -> None:
        app, _, _token_service, _mfa_repo, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user7")
        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})
        client.post("/api/v1/mfa/disable", headers={"Authorization": f"Bearer {token}"})

        resp = client.get("/api/v1/mfa/status", headers={"Authorization": f"Bearer {token}"})
        assert resp.json()["enabled"] is False

    def test_disable_admin_removes_other_user_mfa(self) -> None:
        app, _user_repo, _token_service, _mfa_repo, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Admin user
        admin_token = _register_and_login(client, username="admin1", role="ADMIN")
        target_token = _register_and_login(client, username="target1", role="VIEWER")
        target_id = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {target_token}"}).json()["user_id"]

        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {target_token}"})

        resp = client.post(f"/api/v1/mfa/disable/{target_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

        status_resp = client.get("/api/v1/mfa/status", headers={"Authorization": f"Bearer {target_token}"})
        assert status_resp.json()["enabled"] is False

    def test_recovery_code_authentication(self) -> None:
        app, _, _token_service, _mfa_repo, _recovery_repo, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user8")
        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})

        gen_resp = client.post("/api/v1/mfa/recovery/generate", headers={"Authorization": f"Bearer {token}"})
        recovery_code = gen_resp.json()["codes"][0]

        resp = client.post("/api/v1/mfa/recovery", json={"username": "user8", "password": "Passw0rd!", "recovery_code": recovery_code})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_recovery_code_used_once(self) -> None:
        app, _, _token_service, _, _recovery_repo, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user9")
        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})

        gen_resp = client.post("/api/v1/mfa/recovery/generate", headers={"Authorization": f"Bearer {token}"})
        recovery_code = gen_resp.json()["codes"][0]

        # First use succeeds
        resp1 = client.post("/api/v1/mfa/recovery", json={"username": "user9", "password": "Passw0rd!", "recovery_code": recovery_code})
        assert resp1.status_code == 200

        # Second use fails
        resp2 = client.post("/api/v1/mfa/recovery", json={"username": "user9", "password": "Passw0rd!", "recovery_code": recovery_code})
        assert resp2.status_code == 401

    def test_recovery_rotate(self) -> None:
        app, _, _token_service, _, _recovery_repo, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, username="user10")
        client.post("/api/v1/mfa/enable", headers={"Authorization": f"Bearer {token}"})
        client.post("/api/v1/mfa/recovery/generate", headers={"Authorization": f"Bearer {token}"})

        rotate_resp = client.post("/api/v1/mfa/recovery/rotate", headers={"Authorization": f"Bearer {token}"})
        assert rotate_resp.status_code == 200
        assert len(rotate_resp.json()["codes"]) == 10

    def test_unauthenticated_access_returns_401(self) -> None:
        app, _, _, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/mfa/status")
        assert resp.status_code == 401

    def test_verify_mfa_not_enabled_returns_401(self) -> None:
        app, _, _, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/mfa/verify", json={"username": "nobody", "password": "x", "totp_code": "123456"})
        assert resp.status_code == 401
