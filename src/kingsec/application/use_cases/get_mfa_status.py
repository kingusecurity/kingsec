"""Use case: get MFA status for a user."""
from __future__ import annotations

from ..ports.outbound.mfa_secret_repository import MfaSecretRepository
from .mfa_dto import MfaStatusResponse


class GetMfaStatus:
    """Check whether MFA is enabled for a user."""

    def __init__(self, secret_repo: MfaSecretRepository) -> None:
        self._secret_repo = secret_repo

    def execute(self, user_id: str) -> MfaStatusResponse:
        secret = self._secret_repo.find_by_user_id(user_id)
        enabled = secret is not None and secret.status.value == "enabled"
        return MfaStatusResponse(enabled=enabled)
