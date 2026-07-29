"""The full composition root — where every port meets its concrete adapter.

Module 2.4 provides the *core* composition (``create_application``): configuration,
logging, the DI container, and exception handlers. This module layers the
*adapters* on top: it registers persistence, the Unit of Work, the scanner, the
AI enrichment client, and the report generator, then registers the four application
use cases as DI factories.

This is the ONLY place in the system that names concrete implementations. It is
allowed to import both the application (use cases + ports) and infrastructure
(the ``register_*`` wiring). Adapters never import this module, so the dependency
arrows still point strictly inward.

No business logic lives here — only wiring.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kingsec.application import (
    ActivateUser,
    AdminResetPassword,
    AIPort,
    ApiKeyHasher,
    ApiKeyRepository,
    AssessmentRepository,
    AssignRole,
    AuditEventRepository,
    AuditPublisher,
    CalculateNextRun,
    CancelAssessment,
    ChangePassword,
    CheckAccountLockout,
    CheckRateLimit,
    ClockPort,
    ConfigurationSecurityService,
    CreateApiKey,
    CreateAssessment,
    CreateSchedule,
    CreateSession,
    DeactivateUser,
    DecryptSecret,
    DeleteAssessment,
    DeleteSchedule,
    DeleteSecret,
    DisableMfa,
    DisableSchedule,
    EnableMfa,
    EnableSchedule,
    EncryptionServicePort,
    EncryptSecret,
    EventPublisher,
    FindDueSchedules,
    GenerateRecoveryCodes,
    GenerateReport,
    GetAssessment,
    GetMfaStatus,
    GetSchedule,
    JobRunner,
    JobServicePort,
    ListApiKeys,
    ListAssessments,
    ListFindings,
    ListReports,
    ListSchedules,
    ListSecrets,
    ListUserSessions,
    LockoutRepository,
    Login,
    MfaSecretRepository,
    PasswordHasher,
    PauseSchedule,
    PluginInstallerPort,
    RateLimiterPort,
    RecordAuditEvent,
    RecordFailedAuthentication,
    RecordSuccessfulAuthentication,
    RecoveryCodeRepository,
    RefreshSession,
    RefreshToken,
    RegisterUser,
    ReportGeneratorPort,
    ReportRepository,
    ResetFailedAttempts,
    ResumeSchedule,
    RetrieveSecret,
    RevokeAllSessions,
    RevokeApiKey,
    RevokeSession,
    RotateApiKey,
    RotateRecoveryCodes,
    RotateSecrets,
    ScannerPort,
    ScheduleRepositoryPort,
    SchedulerServicePort,
    SearchAuditEvents,
    SearchUsers,
    SecretProviderPort,
    ServiceAPI,
    SessionRepository,
    StartAssessment,
    StoreSecret,
    SubmitAssessment,
    TerminateOtherSessions,
    TokenService,
    TotpServicePort,
    TriggerScheduleNow,
    UpdateSchedule,
    UseCaseServiceAPI,
    UseRecoveryCode,
    UserRepository,
    ValidateApiKey,
    ValidateConfiguration,
    ValidateSession,
    VerifyMfaCode,
)
from kingsec.infrastructure.ai import register_ai
from kingsec.infrastructure.audit.provisioning import register_audit, register_enterprise_audit
from kingsec.infrastructure.auth.provisioning import (
    register_api_key_auth,
    register_auth,
    register_user_repository,
)
from kingsec.infrastructure.events.provisioning import register_events
from kingsec.infrastructure.jobs import register_jobs
from kingsec.infrastructure.mfa.provisioning import register_mfa
from kingsec.infrastructure.persistence import (
    create_session_factory,
    register_persistence,
    register_unit_of_work,
)
from kingsec.infrastructure.rate_limit.provisioning import register_rate_limiter
from kingsec.infrastructure.reporting import register_reporting
from kingsec.infrastructure.scanner import register_scanner
from kingsec.infrastructure.scheduler.provisioning import register_scheduler
from kingsec.infrastructure.secrets.provisioning import register_secrets
from kingsec.infrastructure.session.provisioning import register_sessions

from .application import Application, create_application
from .container import Container


def create_wired_application(
    *,
    env_file: str | Path | None = None,
    log_stream: Any | None = None,
    ensure_directories: bool = True,
    report_format: str = "pdf",
    brand_name: str = "KingSec",
    validate_migrations: bool = True,
) -> Application:
    """Compose a fully wired, production-ready application.

    Builds the 2.4 core (config, logging, container, exception handlers), then
    registers every infrastructure adapter and the four application use cases so
    they resolve from DI. The returned application is not yet started; use it as
    a context manager or call ``start()``/``stop()``.

    Args:
        env_file: Optional ``.env`` path forwarded to configuration loading.
        log_stream: Optional stream for logs (defaults to stdout).
        ensure_directories: Whether ``start()`` should create the data directory.
        report_format: Report deliverable format, ``"pdf"`` (default) or ``"html"``.
        brand_name: Company-branding placeholder used in reports.
        validate_migrations: Whether to verify the Alembic schema version at
            startup. Pass ``False`` in tests that create a fresh database via
            ``create_schema()`` instead of ``alembic upgrade head``.

    Returns:
        A wired :class:`Application` with every port and use case registered.
    """
    app = create_application(
        env_file=env_file,
        log_stream=log_stream,
        ensure_directories=ensure_directories,
    )
    _register_adapters(
        app,
        report_format=report_format,
        brand_name=brand_name,
        validate_migrations=validate_migrations,
    )
    _register_use_cases(app.container)
    app.logger.info(
        "application composed",
        provider=app.settings.ai.provider,
        report_format=report_format,
    )
    return app


def _register_adapters(
    app: Application,
    *,
    report_format: str,
    brand_name: str,
    validate_migrations: bool = True,
) -> None:
    """Bind every port to its concrete adapter on the container."""
    container = app.container
    settings = app.settings

    # Persistence first: it builds the engine + schema and adds the
    # engine.dispose shutdown hook. The Unit of Work shares that engine.
    engine = register_persistence(container, settings, validate_migrations=validate_migrations)
    session_factory = create_session_factory(engine)
    register_unit_of_work(container, session_factory)

    # Auth: password hasher + JWT token service + user repository.
    register_auth(container, settings, session_factory)
    register_user_repository(container, session_factory)
    register_api_key_auth(container, session_factory, settings)

    # Audit trail: append-only persistence for security events.
    register_audit(container, session_factory)
    register_enterprise_audit(container, session_factory)

    # Organization & team persistence (Phase 14).
    _register_organization_repository(container, session_factory)

    # License & licensing infrastructure (Phase 15).
    _register_license_infrastructure(container, session_factory)

    # Compliance framework mapping (Phase 17).
    _register_compliance_services(container)

    # Asset inventory (Phase 18).
    _register_asset_inventory_services(container, session_factory)

    # Attack surface management (Phase 19).
    _register_attack_surface_services(container, session_factory)

    # Continuous monitoring (Phase 20).
    _register_monitoring_services(container, session_factory)

    # MFA (TOTP) infrastructure.
    register_mfa(container, session_factory)

    # Rate limiting infrastructure (in-memory, thread-safe).
    register_rate_limiter(container, settings)

    # Secrets management infrastructure.
    register_secrets(container, settings, str(settings.storage.data_dir / "secrets.json"))

    # Session management infrastructure.
    register_sessions(container, session_factory)

    # Job service: persistence-backed JobServicePort.
    _register_job_service(container, session_factory)

    # Scheduled scan engine infrastructure.
    register_scheduler(container, session_factory)

    # Capability adapters. AI adds its own http-client.close shutdown hook.
    register_scanner(container, settings)
    register_ai(container, settings)
    _register_ai_services(container)
    register_reporting(container, output_format=report_format, brand_name=brand_name)
    register_jobs(container)
    register_events(container)

    # Plugin installer: filesystem-based, backed by storage data dir.
    from kingsec.application.ports.outbound import PluginInstallerPort
    from kingsec.infrastructure.plugin import PluginInstaller

    def _make_installer(_c: Any) -> PluginInstallerPort:
        return PluginInstaller(base_dir=str(settings.storage.data_dir / "plugins"))

    container.register_factory(PluginInstallerPort, _make_installer)

    # Dashboard repository + analytics service.
    from kingsec.application.analytics_service import AnalyticsService
    from kingsec.application.ports import AnalyticsServicePort, DashboardRepositoryPort
    from kingsec.infrastructure.dashboard.sqlalchemy_repository import SQLAlchemyDashboardRepository

    def _make_dashboard_repo(_c: Any) -> DashboardRepositoryPort:
        return SQLAlchemyDashboardRepository(session_factory())

    container.register_factory(DashboardRepositoryPort, _make_dashboard_repo)

    def _make_analytics_service(c: Any) -> AnalyticsServicePort:
        repo = c.resolve(DashboardRepositoryPort)
        return AnalyticsService(repo)

    container.register_factory(AnalyticsServicePort, _make_analytics_service)

    # Notification service: repository, sender, templates, and service port.
    from kingsec.application.notification_service import NotificationService
    from kingsec.application.ports import (
        NotificationRepositoryPort,
        NotificationSenderPort,
        NotificationServicePort,
        TemplateRendererPort,
    )
    from kingsec.infrastructure.notifications.repository import SQLAlchemyNotificationRepository
    from kingsec.infrastructure.notifications.senders import InAppSender
    from kingsec.infrastructure.notifications.templates import JinjaTemplateRenderer

    def _make_notification_repo(_c: Any) -> NotificationRepositoryPort:
        return SQLAlchemyNotificationRepository(session_factory())

    container.register_factory(NotificationRepositoryPort, _make_notification_repo)

    def _make_notification_sender(_c: Any) -> NotificationSenderPort:
        return InAppSender()

    container.register_factory(NotificationSenderPort, _make_notification_sender)

    def _make_template_renderer(_c: Any) -> TemplateRendererPort:
        return JinjaTemplateRenderer()

    container.register_factory(TemplateRendererPort, _make_template_renderer)

    def _make_notification_service(c: Any) -> NotificationServicePort:
        return NotificationService(
            repo=c.resolve(NotificationRepositoryPort),
            sender=c.resolve(NotificationSenderPort),
            templates=c.resolve(TemplateRendererPort),
            audit=c.resolve(AuditPublisher),
        )

    container.register_factory(NotificationServicePort, _make_notification_service)

    # Authorization service: stateless permission checker.
    from kingsec.application.auth.authorization_service import AuthorizationService

    container.register_instance(AuthorizationService, AuthorizationService())

    # Assessment Execution Engine: in-memory lifecycle tracker (Phase 8).
    from kingsec.application.assessment_execution import AssessmentExecutionEngine

    container.register_instance(AssessmentExecutionEngine, AssessmentExecutionEngine())

    # Enterprise integration services (Phase 13).
    _register_integration_services(container, settings)


def _register_integration_services(container: Container, settings: Any) -> None:
    from kingsec.application.ports.outbound import AuditPublisher
    from kingsec.infrastructure.integrations.email_service import EmailNotificationService
    from kingsec.infrastructure.integrations.siem_service import SIEMExportService
    from kingsec.infrastructure.integrations.ticketing_service import TicketingService
    from kingsec.infrastructure.integrations.webhook_service import WebhookDeliveryService

    def _make_webhook(c: Any) -> WebhookDeliveryService:
        return WebhookDeliveryService(settings.integrations, c.resolve(AuditPublisher))

    def _make_email(c: Any) -> EmailNotificationService:
        return EmailNotificationService(settings.integrations, c.resolve(AuditPublisher))

    def _make_ticketing(c: Any) -> TicketingService:
        return TicketingService(settings.integrations, c.resolve(AuditPublisher))

    def _make_siem(c: Any) -> SIEMExportService:
        return SIEMExportService(settings.integrations, c.resolve(AuditPublisher))

    container.register_factory(WebhookDeliveryService, _make_webhook)
    container.register_factory(EmailNotificationService, _make_email)
    container.register_factory(TicketingService, _make_ticketing)
    container.register_factory(SIEMExportService, _make_siem)


def _register_organization_repository(container: Container, session_factory: Any) -> None:
    from kingsec.application.ports.outbound.organization_repository import OrganizationRepository
    from kingsec.infrastructure.persistence.repositories.organization import SQLAlchemyOrganizationRepository

    def _factory(_c: Any) -> OrganizationRepository:
        return SQLAlchemyOrganizationRepository(session_factory())

    container.register_factory(OrganizationRepository, _factory)


def _register_license_infrastructure(container: Container, session_factory: Any) -> None:
    from kingsec.application.ports.outbound.license_repository import LicenseRepository
    from kingsec.application.ports.outbound.license_validator import LicenseValidator
    from kingsec.application.services.licensing import LicenseActivationService, LicenseGate, LicenseValidatorImpl
    from kingsec.infrastructure.persistence.repositories.license import SQLAlchemyLicenseRepository

    def _repo_factory(_c: Any) -> LicenseRepository:
        return SQLAlchemyLicenseRepository(session_factory())

    container.register_factory(LicenseRepository, _repo_factory)
    container.register_factory(LicenseValidator, lambda c: LicenseValidatorImpl(c.resolve(LicenseRepository)))
    container.register_factory(LicenseGate, lambda c: LicenseGate(c.resolve(LicenseRepository), c.resolve(LicenseValidator)))
    container.register_factory(
        LicenseActivationService,
        lambda c: LicenseActivationService(
            c.resolve(LicenseRepository),
            c.resolve(LicenseValidator),
            c.resolve(LicenseGate),
            c.resolve(AuditPublisher),
        ),
    )


def _register_ai_services(container: Container) -> None:
    from kingsec.application.ai import (
        AIChatService,
        ExecutiveSummaryService,
        ExplainFindingService,
        RemediationAssistantService,
        ReportEnhancementService,
    )
    from kingsec.application.ai.ports import AIQueryPort
    from kingsec.application.ai.cache import PromptCache
    from kingsec.application.ai.redactor import Redactor
    from kingsec.infrastructure.ai.extended_adapter import ExtendedAIAdapter
    from kingsec.infrastructure.ai.adapter import AIProviderAdapter

    container.register_factory(Redactor, lambda c: Redactor())
    container.register_factory(PromptCache, lambda c: PromptCache())
    container.register_factory(
        AIQueryPort,
        lambda c: ExtendedAIAdapter(c.resolve(AIProviderAdapter), c.resolve(AuditPublisher)),
    )
    container.register_factory(
        ExplainFindingService,
        lambda c: ExplainFindingService(c.resolve(AIQueryPort), c.resolve(Redactor)),
    )
    container.register_factory(
        ExecutiveSummaryService,
        lambda c: ExecutiveSummaryService(c.resolve(AIQueryPort), c.resolve(Redactor)),
    )
    container.register_factory(
        RemediationAssistantService,
        lambda c: RemediationAssistantService(c.resolve(AIQueryPort), c.resolve(Redactor)),
    )
    container.register_factory(
        AIChatService,
        lambda c: AIChatService(c.resolve(AIQueryPort), c.resolve(Redactor)),
    )
    container.register_factory(
        ReportEnhancementService,
        lambda c: ReportEnhancementService(c.resolve(AIQueryPort), c.resolve(Redactor)),
    )


def _register_job_service(container: Container, session_factory: Any) -> None:
    """Register ``JobServicePort`` backed by a fresh Unit of Work per resolution.

    Each resolution of ``JobServicePort`` creates a new ``PersistentJobService``
    with its own ``SQLAlchemyUnitOfWork`` so that session lifecycle (close on
    ``__exit__``) does not interfere across callers.
    """
    from kingsec.application.ports.job_service import JobServicePort
    from kingsec.application.services.persistent_job_service import PersistentJobService
    from kingsec.infrastructure.persistence.unit_of_work import SQLAlchemyUnitOfWork

    def _factory(_c: Any) -> JobServicePort:
        uow = SQLAlchemyUnitOfWork(session_factory())
        return PersistentJobService(uow)

    container.register_factory(JobServicePort, _factory)


def _register_use_cases(container: Container) -> None:
    """Register use cases as DI factories.

    Each resolves its port dependencies from the container, so callers do
    ``app.resolve(StartAssessment)`` and get a fully constructed interactor with
    no manual wiring. The UseCaseServiceAPI facade is also registered here,
    wiring the use cases into the ServiceAPI port.
    """
    container.register_factory(
        CreateAssessment,
        lambda c: CreateAssessment(
            c.resolve(AssessmentRepository),
            c.resolve(EventPublisher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        StartAssessment,
        lambda c: StartAssessment(
            c.resolve(AssessmentRepository),
            c.resolve(ScannerPort),
            c.resolve(AIPort),
            c.resolve(EventPublisher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        SubmitAssessment,
        lambda c: SubmitAssessment(
            c.resolve(AssessmentRepository),
            c.resolve(ScannerPort),
            c.resolve(JobRunner),
            c.resolve(AIPort),
            c.resolve(EventPublisher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        CancelAssessment,
        lambda c: CancelAssessment(
            c.resolve(AssessmentRepository),
            c.resolve(EventPublisher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        ListAssessments,
        lambda c: ListAssessments(c.resolve(AssessmentRepository)),
    )
    container.register_factory(
        GetAssessment,
        lambda c: GetAssessment(c.resolve(AssessmentRepository)),
    )
    container.register_factory(
        GenerateReport,
        lambda c: GenerateReport(
            c.resolve(AssessmentRepository),
            c.resolve(ReportRepository),
            c.resolve(ReportGeneratorPort),
            c.resolve(EventPublisher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        DeleteAssessment,
        lambda c: DeleteAssessment(
            c.resolve(AssessmentRepository),
            c.resolve(EventPublisher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        ServiceAPI,
        lambda c: UseCaseServiceAPI(
            c.resolve(CreateAssessment),
            c.resolve(StartAssessment),
            c.resolve(SubmitAssessment),
            c.resolve(CancelAssessment),
            c.resolve(ListAssessments),
            c.resolve(GetAssessment),
            c.resolve(GenerateReport),
            c.resolve(DeleteAssessment),
        ),
    )

    # Auth use cases.
    container.register_factory(
        Login,
        lambda c: Login(
            c.resolve(UserRepository),
            c.resolve(PasswordHasher),
            c.resolve(TokenService),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        RefreshToken,
        lambda c: RefreshToken(
            c.resolve(UserRepository),
            c.resolve(TokenService),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        RegisterUser,
        lambda c: RegisterUser(
            c.resolve(UserRepository),
            c.resolve(PasswordHasher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        AssignRole,
        lambda c: AssignRole(
            c.resolve(UserRepository),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        ChangePassword,
        lambda c: ChangePassword(
            c.resolve(UserRepository),
            c.resolve(PasswordHasher),
            c.resolve(AuditPublisher),
        ),
    )

    # API key use cases.
    container.register_factory(
        CreateApiKey,
        lambda c: CreateApiKey(
            c.resolve(ApiKeyRepository),
            c.resolve(ApiKeyHasher),
        ),
    )
    container.register_factory(
        ListApiKeys,
        lambda c: ListApiKeys(c.resolve(ApiKeyRepository)),
    )
    container.register_factory(
        RevokeApiKey,
        lambda c: RevokeApiKey(c.resolve(ApiKeyRepository)),
    )
    container.register_factory(
        RotateApiKey,
        lambda c: RotateApiKey(
            c.resolve(ApiKeyRepository),
            c.resolve(ApiKeyHasher),
        ),
    )
    container.register_factory(
        ValidateApiKey,
        lambda c: ValidateApiKey(
            c.resolve(ApiKeyRepository),
            c.resolve(ApiKeyHasher),
        ),
    )

    # Enterprise audit use cases.
    container.register_factory(
        RecordAuditEvent,
        lambda c: RecordAuditEvent(c.resolve(AuditEventRepository)),
    )
    container.register_factory(
        SearchAuditEvents,
        lambda c: SearchAuditEvents(c.resolve(AuditEventRepository)),
    )

    # MFA use cases.
    container.register_factory(
        GetMfaStatus,
        lambda c: GetMfaStatus(c.resolve(MfaSecretRepository)),
    )
    container.register_factory(
        EnableMfa,
        lambda c: EnableMfa(
            c.resolve(MfaSecretRepository),
            c.resolve(TotpServicePort),
            c.resolve(AuditEventRepository),
        ),
    )
    container.register_factory(
        DisableMfa,
        lambda c: DisableMfa(
            c.resolve(MfaSecretRepository),
            c.resolve(RecoveryCodeRepository),
            c.resolve(AuditEventRepository),
        ),
    )
    container.register_factory(
        VerifyMfaCode,
        lambda c: VerifyMfaCode(
            c.resolve(UserRepository),
            c.resolve(PasswordHasher),
            c.resolve(TokenService),
            c.resolve(MfaSecretRepository),
            c.resolve(TotpServicePort),
            c.resolve(AuditPublisher),
            c.resolve(AuditEventRepository),
        ),
    )
    container.register_factory(
        GenerateRecoveryCodes,
        lambda c: GenerateRecoveryCodes(c.resolve(RecoveryCodeRepository)),
    )
    container.register_factory(
        UseRecoveryCode,
        lambda c: UseRecoveryCode(
            c.resolve(UserRepository),
            c.resolve(PasswordHasher),
            c.resolve(TokenService),
            c.resolve(MfaSecretRepository),
            c.resolve(RecoveryCodeRepository),
            c.resolve(AuditPublisher),
            c.resolve(AuditEventRepository),
        ),
    )
    container.register_factory(
        RotateRecoveryCodes,
        lambda c: RotateRecoveryCodes(
            c.resolve(RecoveryCodeRepository),
            c.resolve(AuditEventRepository),
        ),
    )

    # Session management use cases.
    container.register_factory(
        CreateSession,
        lambda c: CreateSession(
            c.resolve(SessionRepository),
            c.resolve(ClockPort),
        ),
    )
    container.register_factory(
        ValidateSession,
        lambda c: ValidateSession(
            c.resolve(SessionRepository),
            c.resolve(ClockPort),
        ),
    )
    container.register_factory(
        RefreshSession,
        lambda c: RefreshSession(c.resolve(SessionRepository), c.resolve(TokenService)),
    )
    container.register_factory(
        RevokeSession,
        lambda c: RevokeSession(c.resolve(SessionRepository), c.resolve(TokenService)),
    )
    container.register_factory(
        RevokeAllSessions,
        lambda c: RevokeAllSessions(c.resolve(SessionRepository), c.resolve(TokenService)),
    )
    container.register_factory(
        ListUserSessions,
        lambda c: ListUserSessions(c.resolve(SessionRepository)),
    )
    container.register_factory(
        TerminateOtherSessions,
        lambda c: TerminateOtherSessions(c.resolve(SessionRepository), c.resolve(TokenService)),
    )

    # Rate limiting use cases.
    container.register_factory(
        CheckRateLimit,
        lambda c: CheckRateLimit(c.resolve(RateLimiterPort)),
    )
    container.register_factory(
        RecordFailedAuthentication,
        lambda c: RecordFailedAuthentication(
            c.resolve(LockoutRepository),
            c.resolve(ClockPort),
        ),
    )
    container.register_factory(
        RecordSuccessfulAuthentication,
        lambda c: RecordSuccessfulAuthentication(c.resolve(LockoutRepository)),
    )
    container.register_factory(
        CheckAccountLockout,
        lambda c: CheckAccountLockout(c.resolve(LockoutRepository), c.resolve(ClockPort)),
    )
    container.register_factory(
        ResetFailedAttempts,
        lambda c: ResetFailedAttempts(c.resolve(LockoutRepository)),
    )

    # Secrets management use cases.
    container.register_factory(
        EncryptSecret,
        lambda c: EncryptSecret(c.resolve(EncryptionServicePort)),
    )
    container.register_factory(
        DecryptSecret,
        lambda c: DecryptSecret(c.resolve(EncryptionServicePort)),
    )
    container.register_factory(
        StoreSecret,
        lambda c: StoreSecret(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )
    container.register_factory(
        RetrieveSecret,
        lambda c: RetrieveSecret(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )
    container.register_factory(
        DeleteSecret,
        lambda c: DeleteSecret(c.resolve(SecretProviderPort)),
    )
    container.register_factory(
        ListSecrets,
        lambda c: ListSecrets(c.resolve(SecretProviderPort)),
    )
    container.register_factory(
        RotateSecrets,
        lambda c: RotateSecrets(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )
    container.register_factory(
        ValidateConfiguration,
        lambda c: ValidateConfiguration(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )
    container.register_factory(
        ConfigurationSecurityService,
        lambda c: ConfigurationSecurityService(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )

    # Scheduled scan use cases.
    container.register_factory(
        CreateSchedule,
        lambda c: CreateSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        UpdateSchedule,
        lambda c: UpdateSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        DeleteSchedule,
        lambda c: DeleteSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        PauseSchedule,
        lambda c: PauseSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        ResumeSchedule,
        lambda c: ResumeSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        EnableSchedule,
        lambda c: EnableSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        DisableSchedule,
        lambda c: DisableSchedule(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        TriggerScheduleNow,
        lambda c: TriggerScheduleNow(
            c.resolve(ScheduleRepositoryPort),
            c.resolve(JobServicePort),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        ListSchedules,
        lambda c: ListSchedules(c.resolve(ScheduleRepositoryPort)),
    )
    container.register_factory(
        GetSchedule,
        lambda c: GetSchedule(c.resolve(ScheduleRepositoryPort)),
    )
    container.register_factory(
        FindDueSchedules,
        lambda c: FindDueSchedules(c.resolve(ScheduleRepositoryPort)),
    )
    container.register_factory(
        CalculateNextRun,
        lambda c: CalculateNextRun(c.resolve(SchedulerServicePort)),
    )

    # Findings use cases.
    container.register_factory(
        ListFindings,
        lambda c: ListFindings(c.resolve(AssessmentRepository)),
    )

    # Reports use cases.
    container.register_factory(
        ListReports,
        lambda c: ListReports(c.resolve(ReportRepository)),
    )

    # Admin user use cases.
    container.register_factory(
        DeactivateUser,
        lambda c: DeactivateUser(
            c.resolve(UserRepository),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        ActivateUser,
        lambda c: ActivateUser(
            c.resolve(UserRepository),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        AdminResetPassword,
        lambda c: AdminResetPassword(
            c.resolve(UserRepository),
            c.resolve(PasswordHasher),
            c.resolve(AuditPublisher),
        ),
    )
    container.register_factory(
        SearchUsers,
        lambda c: SearchUsers(c.resolve(UserRepository)),
    )


def _register_compliance_services(container: Container) -> None:
    from kingsec.application.compliance import (
        ComplianceCoverageCalculator,
        ComplianceGapAnalyzer,
        ComplianceMapper,
        ComplianceReportGenerator,
    )

    container.register_instance(ComplianceMapper, ComplianceMapper())
    container.register_instance(ComplianceCoverageCalculator, ComplianceCoverageCalculator())
    container.register_instance(ComplianceGapAnalyzer, ComplianceGapAnalyzer())
    container.register_factory(
        ComplianceReportGenerator,
        lambda c: ComplianceReportGenerator(
            c.resolve(ComplianceMapper),
            c.resolve(ComplianceCoverageCalculator),
            c.resolve(ComplianceGapAnalyzer),
        ),
    )


def _register_attack_surface_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.ports.attack_surface import AttackSurfaceRepositoryPort
    from kingsec.application.services.attack_surface import AttackSurfaceService
    from kingsec.infrastructure.persistence.repositories.attack_surface import (
        SQLAlchemyAttackSurfaceRepository,
    )

    def _make_repo(_c: Any) -> AttackSurfaceRepositoryPort:
        return SQLAlchemyAttackSurfaceRepository(session_factory())

    container.register_factory(AttackSurfaceRepositoryPort, _make_repo)
    container.register_factory(
        AttackSurfaceService,
        lambda c: AttackSurfaceService(
            repo=c.resolve(AttackSurfaceRepositoryPort),
        ),
    )


def _register_monitoring_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.monitoring.alert_manager import AlertManager
    from kingsec.application.monitoring.dashboard import MonitoringDashboardService
    from kingsec.application.monitoring.detectors import AssetChangeDetector, FindingChangeDetector
    from kingsec.application.monitoring.ports import (
        AlertRepositoryPort,
        AuditPublisherPort,
        MonitoringDashboardRepositoryPort,
        MonitoringEventRepositoryPort,
        NotificationSenderPort,
        RuleRepositoryPort,
    )
    from kingsec.application.monitoring.rules import MonitoringRuleEngine
    from kingsec.application.monitoring.scheduler import MonitoringScheduler
    from kingsec.application.monitoring.service import MonitoringService
    from kingsec.infrastructure.persistence.repositories.monitoring import (
        SQLAlchemyAlertRepository,
        SQLAlchemyMonitoringDashboardRepository,
        SQLAlchemyMonitoringEventRepository,
        SQLAlchemyRuleRepository,
    )

    def _make_event_repo(_c: Any) -> MonitoringEventRepositoryPort:
        return SQLAlchemyMonitoringEventRepository(session_factory())

    def _make_alert_repo(_c: Any) -> AlertRepositoryPort:
        return SQLAlchemyAlertRepository(session_factory())

    def _make_rule_repo(_c: Any) -> RuleRepositoryPort:
        return SQLAlchemyRuleRepository(session_factory())

    def _make_dashboard_repo(_c: Any) -> MonitoringDashboardRepositoryPort:
        return SQLAlchemyMonitoringDashboardRepository(session_factory())

    container.register_factory(MonitoringEventRepositoryPort, _make_event_repo)
    container.register_factory(AlertRepositoryPort, _make_alert_repo)
    container.register_factory(RuleRepositoryPort, _make_rule_repo)
    container.register_factory(MonitoringDashboardRepositoryPort, _make_dashboard_repo)

    container.register_instance(MonitoringRuleEngine, MonitoringRuleEngine())
    container.register_instance(AssetChangeDetector, AssetChangeDetector())
    container.register_instance(FindingChangeDetector, FindingChangeDetector())

    container.register_factory(
        AlertManager,
        lambda c: AlertManager(
            alert_repo=c.resolve(AlertRepositoryPort),
            notification_sender=c.resolve(NotificationSenderPort) if c.has(NotificationSenderPort) else None,
            audit_publisher=c.resolve(AuditPublisherPort) if c.has(AuditPublisherPort) else None,
        ),
    )

    container.register_factory(
        MonitoringService,
        lambda c: MonitoringService(
            event_repo=c.resolve(MonitoringEventRepositoryPort),
            rule_repo=c.resolve(RuleRepositoryPort),
            alert_manager=c.resolve(AlertManager),
            rule_engine=c.resolve(MonitoringRuleEngine),
            asset_detector=c.resolve(AssetChangeDetector),
            finding_detector=c.resolve(FindingChangeDetector),
            audit_publisher=c.resolve(AuditPublisherPort) if c.has(AuditPublisherPort) else None,
        ),
    )

    container.register_factory(
        MonitoringDashboardService,
        lambda c: MonitoringDashboardService(
            dashboard_repo=c.resolve(MonitoringDashboardRepositoryPort),
            event_repo=c.resolve(MonitoringEventRepositoryPort),
            alert_repo=c.resolve(AlertRepositoryPort),
            rule_repo=c.resolve(RuleRepositoryPort),
        ),
    )

    container.register_factory(
        MonitoringScheduler,
        lambda c: MonitoringScheduler(
            monitoring_service=c.resolve(MonitoringService),
            asset_detector=c.resolve(AssetChangeDetector),
            finding_detector=c.resolve(FindingChangeDetector),
        ),
    )


def _register_asset_inventory_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.ports.asset_inventory import AssetInventoryRepositoryPort
    from kingsec.application.services.asset_inventory import AssetInventoryService
    from kingsec.infrastructure.persistence.repositories.asset_inventory import (
        SQLAlchemyAssetInventoryRepository,
    )

    def _make_repo(_c: Any) -> AssetInventoryRepositoryPort:
        return SQLAlchemyAssetInventoryRepository(session_factory())

    container.register_factory(AssetInventoryRepositoryPort, _make_repo)
    container.register_factory(
        AssetInventoryService,
        lambda c: AssetInventoryService(
            repo=c.resolve(AssetInventoryRepositoryPort),
        ),
    )
