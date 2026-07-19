"""Port definitions - the boundaries between the core and the outside."""

from .inbound import ServiceAPI
from .job_service import JobServicePort
from .outbound.api_key_hasher import ApiKeyHasher
from .outbound.api_key_repository import ApiKeyRepository
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
    "Asset",
    "AssetRepositoryPort",
    "AuditPublisher",
    "EventPublisher",
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
]
