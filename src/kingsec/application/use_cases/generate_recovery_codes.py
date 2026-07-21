"""Use case: generate initial recovery codes for MFA."""
from __future__ import annotations

from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.domain.mfa import MfaRecoveryCode, RecoveryCodeStatus

from .mfa_dto import GenerateRecoveryCodesRequest, GenerateRecoveryCodesResponse


class GenerateRecoveryCodes:
    """Generate initial recovery codes (plaintext returned once, stored hashed)."""

    def __init__(self, recovery_repo: RecoveryCodeRepository) -> None:
        self._recovery_repo = recovery_repo

    def execute(self, request: GenerateRecoveryCodesRequest) -> GenerateRecoveryCodesResponse:
        import hashlib
        import os

        plaintext_codes: list[str] = []
        hashed_codes: list[MfaRecoveryCode] = []

        for _ in range(10):
            code = f"{os.urandom(10).hex()}-{os.urandom(10).hex()}"
            plaintext_codes.append(code)
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            hashed_codes.append(MfaRecoveryCode(code_hash=code_hash, status=RecoveryCodeStatus.ACTIVE))

        self._recovery_repo.save_batch(request.user_id, hashed_codes)

        return GenerateRecoveryCodesResponse(codes=tuple(plaintext_codes))
