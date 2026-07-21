"""DI wiring for MFA (TOTP) infrastructure."""
from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.application.ports.outbound.totp_service import TotpServicePort
from kingsec.infrastructure.persistence.mfa_secret_repository import SqlAlchemyMfaSecretRepository
from kingsec.infrastructure.persistence.recovery_code_repository import (
    SqlAlchemyRecoveryCodeRepository,
)

from .totp_service import TotpService

if TYPE_CHECKING:
    from sqlalchemy.orm import sessionmaker


def register_mfa(container: object, session_factory: sessionmaker) -> None:
    """Register MFA infrastructure on the DI container."""
    totp_service = TotpService()
    secret_repo = SqlAlchemyMfaSecretRepository(session_factory)
    recovery_repo = SqlAlchemyRecoveryCodeRepository(session_factory)

    container.register_instance(TotpServicePort, totp_service)
    container.register_instance(MfaSecretRepository, secret_repo)
    container.register_instance(RecoveryCodeRepository, recovery_repo)
