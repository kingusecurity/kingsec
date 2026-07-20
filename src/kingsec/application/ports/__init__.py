"""Port definitions - the boundaries between the core and the outside."""

from .inbound import ServiceAPI
from .job_service import JobServicePort
from .outbound.api_key_hasher import ApiKeyHasher
from .outbound.encryption_service import EncryptionServicePort
from .outbound.secret_provider import SecretProviderPort
from .outbound.api_key_repository import ApiKeyRepository
from .outbound.audit_event_repository import AuditEventRepository
from .outbound.clock_port import ClockPort
from .outbound.lockout_repository import LockoutRepository
from .outbound.mfa_secret_repository import MfaSecretRepository
from .outbound.rate_limiter import RateLimiterPort
from .outbound.recovery_code_repository import RecoveryCodeRepository
from .outbound.session_repository import SessionRepository
from .outbound.totp_service import TotpServicePort
from .outbound.audit_publisher import AuditPublisher
from .outbound.event_publisher import EventPublisher
from .outbound.job_runner import JobRunner
from .outbound.password_hasher import PasswordHasher
from .outbound.token_service import TokenClaims, TokenExpiredError, TokenInvalidError, TokenService
from .outbound.user_repository import UserRepository
from .report_service import ReportGenerationResult, ReportServicePort
from .repositories import (
    AssessmentRepository,
    Asset,
    AssetRepositoryPort,
    JobRepositoryPort,
    ReportRepository,
    ScanRepositoryPort,
)
from .scanner_executor import ScannerExecutor
from .scanner_plugin import ScannerPluginPort
from .scanner_registry import ScannerPluginRegistry
from .services import AIPort, ReportGeneratorPort, ScannerPort
from .unit_of_work import UnitOfWork, UnitOfWorkFactory

__all__ = [
    "AIPort",
    "ApiKeyHasher",
    "ApiKeyRepository",
    "AssessmentRepository",
    "AuditEventRepository",
    "Asset",
    "AssetRepositoryPort",
    "AuditPublisher",
    "ClockPort",
    "EventPublisher",
    "LockoutRepository",
    "MfaSecretRepository",
    "RateLimiterPort",
    "RecoveryCodeRepository",
    "SessionRepository",
    "TotpServicePort",
    "JobRepositoryPort",
    "JobRunner",
    "JobServicePort",
    "PasswordHasher",
    "ReportGenerationResult",
    "ReportGeneratorPort",
    "ReportRepository",
    "ReportServicePort",
    "ScanRepositoryPort",
    "ScannerExecutor",
    "ScannerPluginPort",
    "ScannerPluginRegistry",
    "ScannerPort",
    "ServiceAPI",
    "TokenClaims",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenService",
    "UnitOfWork",
    "UnitOfWorkFactory",
    "UserRepository",
    "EncryptionServicePort",
    "SecretProviderPort",
]
