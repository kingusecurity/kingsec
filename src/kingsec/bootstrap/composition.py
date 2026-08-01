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

    # Threat intelligence & CVE enrichment (Phase 21).
    _register_threat_intelligence_services(container, session_factory)

    # AI Security Copilot (Phase 22).
    _register_copilot_services(container, session_factory)

    # Security Automation, Playbooks & Incident Response (Phase 23).
    _register_playbook_services(container, session_factory)

    # Plugin SDK & Extension Framework (Phase 24).
    _register_plugin_sdk_services(container, session_factory)

    # Distributed Scan Workers & Job Queue (Phase 25).
    _register_distributed_worker_services(container, session_factory)

    # Enterprise Identity & SSO (Phase 26).
    _register_idp_services(container, session_factory)

    # Backup, Disaster Recovery & High Availability (Phase 27).
    _register_backup_services(container, session_factory)

    # Performance, Caching & Metrics (Phase 28).
    _register_performance_services(container)

    # Production service & its outbound port dependencies.
    _register_production_services(container, session_factory)

    # Deployment diagnostics, upgrade, release-audit & telemetry (Phase 32).
    _register_deployment_services(container, settings)

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

    # --- Queue, Plugin, Agent, Pipeline services (Phase 34) ---
    _register_queue_services(container, session_factory)
    _register_plugin_services(container)
    _register_agent_services(container)
    _register_pipeline_services(container, session_factory)

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
    from kingsec.application.ai.cache import PromptCache
    from kingsec.application.ai.ports import AIQueryPort
    from kingsec.application.ai.redactor import Redactor
    from kingsec.infrastructure.ai.adapter import AIProviderAdapter
    from kingsec.infrastructure.ai.extended_adapter import ExtendedAIAdapter

    container.register_factory(Redactor, lambda c: Redactor())
    container.register_factory(PromptCache, lambda c: PromptCache())
    # AIProviderAdapter is the concrete class; register it by resolving AIPort
    # (which register_ai binds to the same instance).
    container.register_factory(
        AIProviderAdapter,
        lambda c: c.resolve(AIPort),
    )
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
    from kingsec.application.assessment_execution import AssessmentExecutionEngine

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
            c.resolve(AssessmentExecutionEngine),
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


def _register_threat_intelligence_services(container: Container, session_factory: Any) -> None:
    from kingsec.adapters.outbound.threat_intelligence.cisa_kev_provider import CisaKevApiProvider
    from kingsec.adapters.outbound.threat_intelligence.epss_provider import EpssApiProvider
    from kingsec.adapters.outbound.threat_intelligence.mitre_provider import MitreCveProvider
    from kingsec.adapters.outbound.threat_intelligence.nvd_provider import NvdApiProvider
    from kingsec.application.threat_intelligence.enrichment import (
        CveEnrichmentService,
        CvssService,
        EpssService,
        KevService,
    )
    from kingsec.application.threat_intelligence.feed_aggregator import ThreatFeedAggregator
    from kingsec.application.threat_intelligence.ports import (
        AuditPublisherPort as TIAuditPublisherPort,
    )
    from kingsec.application.threat_intelligence.ports import (
        CacheServicePort as TICacheServicePort,
    )
    from kingsec.application.threat_intelligence.ports import (
        CveRepositoryPort,
        EpssProviderPort,
        KevProviderPort,
        MitreCveProviderPort,
        NvdProviderPort,
        ThreatFeedRepositoryPort,
    )
    from kingsec.application.threat_intelligence.reports import ThreatReportGenerator
    from kingsec.application.threat_intelligence.risk_calculator import ThreatRiskCalculator
    from kingsec.application.threat_intelligence.service import ThreatIntelligenceService
    from kingsec.infrastructure.persistence.repositories.threat_intelligence import (
        SQLAlchemyCveRepository,
        SQLAlchemyThreatFeedRepository,
    )

    def _make_cve_repo(_c: Any) -> CveRepositoryPort:
        return SQLAlchemyCveRepository(session_factory())

    def _make_feed_repo(_c: Any) -> ThreatFeedRepositoryPort:
        return SQLAlchemyThreatFeedRepository(session_factory())

    container.register_factory(CveRepositoryPort, _make_cve_repo)
    container.register_factory(ThreatFeedRepositoryPort, _make_feed_repo)

    container.register_instance(NvdProviderPort, NvdApiProvider())
    container.register_instance(EpssProviderPort, EpssApiProvider())
    container.register_instance(KevProviderPort, CisaKevApiProvider())
    container.register_instance(MitreCveProviderPort, MitreCveProvider())

    container.register_factory(
        EpssService,
        lambda c: EpssService(
            epss_provider=c.resolve(EpssProviderPort) if c.has(EpssProviderPort) else None,
        ),
    )

    container.register_factory(
        KevService,
        lambda c: KevService(
            kev_provider=c.resolve(KevProviderPort) if c.has(KevProviderPort) else None,
        ),
    )

    container.register_factory(
        CveEnrichmentService,
        lambda c: CveEnrichmentService(
            nvd_provider=c.resolve(NvdProviderPort) if c.has(NvdProviderPort) else None,
            epss_provider=c.resolve(EpssProviderPort) if c.has(EpssProviderPort) else None,
            kev_provider=c.resolve(KevProviderPort) if c.has(KevProviderPort) else None,
            mitre_provider=c.resolve(MitreCveProviderPort) if c.has(MitreCveProviderPort) else None,
        ),
    )

    container.register_factory(
        ThreatFeedAggregator,
        lambda c: ThreatFeedAggregator(
            nvd_provider=c.resolve(NvdProviderPort) if c.has(NvdProviderPort) else None,
            kev_provider=c.resolve(KevProviderPort) if c.has(KevProviderPort) else None,
            epss_provider=c.resolve(EpssProviderPort) if c.has(EpssProviderPort) else None,
            mitre_provider=c.resolve(MitreCveProviderPort) if c.has(MitreCveProviderPort) else None,
            feed_repo=c.resolve(ThreatFeedRepositoryPort) if c.has(ThreatFeedRepositoryPort) else None,
            cache=c.resolve(TICacheServicePort) if c.has(TICacheServicePort) else None,
            audit=c.resolve(TIAuditPublisherPort) if c.has(TIAuditPublisherPort) else None,
        ),
    )

    container.register_factory(
        ThreatIntelligenceService,
        lambda c: ThreatIntelligenceService(
            cve_repo=c.resolve(CveRepositoryPort),
            enrichment=c.resolve(CveEnrichmentService),
            epss_service=c.resolve(EpssService),
            kev_service=c.resolve(KevService),
            feed_repo=c.resolve(ThreatFeedRepositoryPort) if c.has(ThreatFeedRepositoryPort) else None,
            cache=c.resolve(TICacheServicePort) if c.has(TICacheServicePort) else None,
            audit=c.resolve(TIAuditPublisherPort) if c.has(TIAuditPublisherPort) else None,
        ),
    )

    container.register_factory(
        ThreatReportGenerator,
        lambda c: ThreatReportGenerator(
            cve_repo=c.resolve(CveRepositoryPort),
            feed_repo=c.resolve(ThreatFeedRepositoryPort) if c.has(ThreatFeedRepositoryPort) else None,
            audit=c.resolve(TIAuditPublisherPort) if c.has(TIAuditPublisherPort) else None,
        ),
    )

    container.register_instance(ThreatRiskCalculator, ThreatRiskCalculator)
    container.register_instance(CvssService, CvssService)


def _register_copilot_services(container: Container, session_factory: Any) -> None:
    from kingsec.application import AssessmentRepository
    from kingsec.application.ai.ports import AIQueryPort
    from kingsec.application.ai.redactor import Redactor
    from kingsec.application.ai_copilot.context_builder import (
        CopilotContextBuilder,
    )
    from kingsec.application.ai_copilot.copilot_service import CopilotService
    from kingsec.application.ai_copilot.export_service import CopilotExportService
    from kingsec.application.ai_copilot.notes_service import InvestigationNotesService
    from kingsec.application.ai_copilot.ports import (
        AuditPublisherPort as CopilotAuditPublisherPort,
    )
    from kingsec.application.ai_copilot.ports import (
        CacheServicePort as CopilotCacheServicePort,
    )
    from kingsec.application.ai_copilot.ports import (
        CopilotConversationRepositoryPort,
        InvestigationNoteRepositoryPort,
    )
    from kingsec.application.monitoring.ports import AlertRepositoryPort as MonitoringAlertRepositoryPort
    from kingsec.application.ports.attack_surface import AttackSurfaceRepositoryPort
    from kingsec.application.ports.repositories import Asset
    from kingsec.application.threat_intelligence.ports import CveRepositoryPort as TICveRepositoryPort
    from kingsec.infrastructure.persistence.repositories.copilot import (
        SQLAlchemyCopilotConversationRepository,
        SQLAlchemyInvestigationNoteRepository,
    )

    def _make_conv_repo(_c: Any) -> CopilotConversationRepositoryPort:
        return SQLAlchemyCopilotConversationRepository(session_factory())

    def _make_note_repo(_c: Any) -> InvestigationNoteRepositoryPort:
        return SQLAlchemyInvestigationNoteRepository(session_factory())

    container.register_factory(CopilotConversationRepositoryPort, _make_conv_repo)
    container.register_factory(InvestigationNoteRepositoryPort, _make_note_repo)

    container.register_factory(
        CopilotContextBuilder,
        lambda c: CopilotContextBuilder(
            finding_repo=None,
            assessment_repo=c.resolve(AssessmentRepository) if c.has(AssessmentRepository) else None,
            asset_repo=c.resolve(Asset) if c.has(Asset) else None,
            cve_repo=c.resolve(TICveRepositoryPort) if c.has(TICveRepositoryPort) else None,
            alert_repo=c.resolve(MonitoringAlertRepositoryPort) if c.has(MonitoringAlertRepositoryPort) else None,
            exposure_repo=c.resolve(AttackSurfaceRepositoryPort) if c.has(AttackSurfaceRepositoryPort) else None,
        ),
    )

    container.register_factory(
        CopilotService,
        lambda c: CopilotService(
            ai=c.resolve(AIQueryPort),
            context_builder=c.resolve(CopilotContextBuilder),
            conversation_repo=c.resolve(CopilotConversationRepositoryPort),
            redactor=c.resolve(Redactor) if c.has(Redactor) else None,
            cache=c.resolve(CopilotCacheServicePort) if c.has(CopilotCacheServicePort) else None,
            audit=c.resolve(CopilotAuditPublisherPort) if c.has(CopilotAuditPublisherPort) else None,
        ),
    )

    container.register_factory(
        InvestigationNotesService,
        lambda c: InvestigationNotesService(
            note_repo=c.resolve(InvestigationNoteRepositoryPort),
            audit=c.resolve(CopilotAuditPublisherPort) if c.has(CopilotAuditPublisherPort) else None,
        ),
    )

    container.register_factory(
        CopilotExportService,
        lambda c: CopilotExportService(
            conversation_repo=c.resolve(CopilotConversationRepositoryPort),
            note_repo=c.resolve(InvestigationNoteRepositoryPort),
            context_builder=c.resolve(CopilotContextBuilder),
            audit=c.resolve(CopilotAuditPublisherPort) if c.has(CopilotAuditPublisherPort) else None,
        ),
    )


def _register_playbook_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.playbooks.actions import ActionExecutor
    from kingsec.application.playbooks.engine import PlaybookEngine
    from kingsec.application.playbooks.ports import (
        ExecutionHistoryRepositoryPort,
        PlaybookAuditPort,
        PlaybookRepositoryPort,
    )
    from kingsec.application.playbooks.service import PlaybookService
    from kingsec.application.ports.outbound import AuditPublisher
    from kingsec.infrastructure.persistence.repositories.playbook import (
        SQLAlchemyExecutionHistoryRepository,
        SQLAlchemyPlaybookRepository,
    )

    def _make_pb_repo(_c: Any) -> PlaybookRepositoryPort:
        return SQLAlchemyPlaybookRepository(session_factory())

    def _make_hist_repo(_c: Any) -> ExecutionHistoryRepositoryPort:
        return SQLAlchemyExecutionHistoryRepository(session_factory())

    def _make_action_executor(_c: Any) -> ActionExecutor:
        return ActionExecutor()

    container.register_factory(PlaybookRepositoryPort, _make_pb_repo)
    container.register_factory(ExecutionHistoryRepositoryPort, _make_hist_repo)
    container.register_factory(ActionExecutor, _make_action_executor)

    container.register_factory(
        PlaybookEngine,
        lambda c: PlaybookEngine(
            history_repo=c.resolve(ExecutionHistoryRepositoryPort),
            action_executor=c.resolve(ActionExecutor),
            audit=c.resolve(PlaybookAuditPort) if c.has(PlaybookAuditPort) else None,
        ),
    )

    container.register_factory(
        PlaybookService,
        lambda c: PlaybookService(
            playbook_repo=c.resolve(PlaybookRepositoryPort),
            engine=c.resolve(PlaybookEngine),
            history_repo=c.resolve(ExecutionHistoryRepositoryPort),
            audit=c.resolve(PlaybookAuditPort) if c.has(PlaybookAuditPort) else c.resolve(AuditPublisher) if c.has(AuditPublisher) else None,
        ),
    )


def _register_plugin_sdk_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.plugin_sdk.loader import PluginLoader
    from kingsec.application.plugin_sdk.registry import PluginMarketplace, PluginRegistry
    from kingsec.infrastructure.config.settings import Settings

    settings = container.resolve(Settings) if container.has(Settings) else None

    def _make_loader(_c: Any) -> PluginLoader:
        from pathlib import Path
        plugins_dir = Path(settings.storage.data_dir) / "plugins" if settings else Path("./plugins")
        return PluginLoader(plugins_dir)

    def _make_registry(c: Any) -> PluginRegistry:
        loader = c.resolve(PluginLoader)
        registry = PluginRegistry(loader)
        registry.discover()
        return registry

    def _make_marketplace(_c: Any) -> PluginMarketplace:
        mp = PluginMarketplace()
        mp.seed_default_catalog()
        return mp

    container.register_factory(PluginLoader, _make_loader)
    container.register_factory(PluginRegistry, _make_registry)
    container.register_factory(PluginMarketplace, _make_marketplace)


def _register_queue_services(container: Container, session_factory: Any) -> None:
    """Register queue service and its dependencies."""
    from kingsec.application.ports.outbound import QueueRepositoryPort, SchedulerPolicyPort
    from kingsec.application.ports.queue_service import QueueServicePort
    from kingsec.application.queue_service import QueueService
    from kingsec.infrastructure.queue import DefaultSchedulingPolicy, InMemoryQueueRepository

    container.register_factory(
        QueueRepositoryPort,
        lambda c: InMemoryQueueRepository(),
    )
    container.register_factory(SchedulerPolicyPort, lambda c: DefaultSchedulingPolicy())
    container.register_factory(
        QueueServicePort,
        lambda c: QueueService(
            repo=c.resolve(QueueRepositoryPort),
            policy=c.resolve(SchedulerPolicyPort),
        ),
    )


def _register_plugin_services(container: Container) -> None:
    """Register plugin service and its dependencies."""
    from kingsec.application.ports.outbound import PluginRepositoryPort, PluginValidatorPort
    from kingsec.application.ports.plugin_service import PluginServicePort
    from kingsec.application.plugin_service import PluginService
    from kingsec.infrastructure.plugin import InMemoryPluginRepository, PluginValidator

    container.register_factory(PluginRepositoryPort, lambda c: InMemoryPluginRepository())
    container.register_factory(PluginValidatorPort, lambda c: PluginValidator())
    container.register_factory(
        PluginServicePort,
        lambda c: PluginService(
            repo=c.resolve(PluginRepositoryPort),
            installer=c.resolve(PluginInstallerPort),
            validator=c.resolve(PluginValidatorPort),
        ),
    )


def _register_agent_services(container: Container) -> None:
    """Register agent service and its dependencies."""
    from kingsec.application.ports.outbound import AgentDispatcherPort, AgentRepositoryPort
    from kingsec.application.ports.agent_service import AgentServicePort
    from kingsec.application.agent_service import AgentService
    from kingsec.infrastructure.agent import InMemoryAgentDispatcher, InMemoryAgentRepository

    container.register_factory(AgentRepositoryPort, lambda c: InMemoryAgentRepository())
    container.register_factory(AgentDispatcherPort, lambda c: InMemoryAgentDispatcher())
    container.register_factory(
        AgentServicePort,
        lambda c: AgentService(
            repo=c.resolve(AgentRepositoryPort),
            dispatcher=c.resolve(AgentDispatcherPort),
        ),
    )


def _register_pipeline_services(container: Container, session_factory: Any) -> None:
    """Register pipeline service and its dependencies."""
    from kingsec.application.ports.outbound import (
        AgentDispatcherPort,
        PipelineOrchestratorPort,
        PipelineRepositoryPort,
    )
    from kingsec.application.ports.pipeline_service import PipelineServicePort
    from kingsec.application.ports.notification_service import NotificationServicePort
    from kingsec.application.ports.queue_service import QueueServicePort as QueueInboundPort
    from kingsec.application.ports.report_service import ReportGenerationResult, ReportServicePort
    from kingsec.application.pipeline_service import PipelineService
    from kingsec.infrastructure.pipeline import InMemoryPipelineRepository, PipelineOrchestrator

    container.register_factory(PipelineRepositoryPort, lambda c: InMemoryPipelineRepository())

    class _StubReportService(ReportServicePort):
        def generate_report(self, scan_id: str) -> ReportGenerationResult:
            from datetime import UTC, datetime
            return ReportGenerationResult(
                report_id=str(__import__("uuid").uuid4()),
                status="completed",
                generated_at=datetime.now(UTC),
                finding_count=0,
            )

        def get_report(self, report_id: str) -> dict[str, Any]:
            return {"report_id": report_id, "status": "completed", "findings": []}

        def get_summary(self, report_id: str) -> dict[str, Any]:
            return {"report_id": report_id, "risk_summary": {}, "executive_summary": ""}

        def get_formats(self, report_id: str) -> list[str]:
            return ["pdf", "json"]

        def render_report(self, report_id: str, format_name: str) -> Any:
            from kingsec.application.dto import RenderedReport
            return RenderedReport(
                content=b"",
                media_type="application/octet-stream",
                filename=f"{report_id}.{format_name}",
            )

    def _make_orchestrator(c: Any) -> PipelineOrchestratorPort:
        return PipelineOrchestrator(
            job_service=c.resolve(JobServicePort),
            queue_service=c.resolve(QueueInboundPort),
            agent_dispatcher=c.resolve(AgentDispatcherPort),
            report_service=_StubReportService(),
            notification_service=c.resolve(NotificationServicePort),
            audit=c.resolve(AuditPublisher),
        )

    container.register_factory(PipelineOrchestratorPort, _make_orchestrator)
    container.register_factory(
        PipelineServicePort,
        lambda c: PipelineService(
            repo=c.resolve(PipelineRepositoryPort),
            orchestrator=c.resolve(PipelineOrchestratorPort),
            audit=c.resolve(AuditPublisher),
        ),
    )


def _register_distributed_worker_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.distributed.job_dispatcher import JobDispatcher, JobLeaseManager
    from kingsec.application.distributed.ports import (
        DeadLetterRepositoryPort,
        JobLeaseRepositoryPort,
        JobQueueRepositoryPort,
        WorkerRepositoryPort,
    )
    from kingsec.application.distributed.retry_manager import DeadLetterService, RetryManager
    from kingsec.application.distributed.scheduler import CapabilityMatchingScheduler
    from kingsec.application.distributed.worker_service import HeartbeatManager, WorkerRegistrationService
    from kingsec.infrastructure.persistence.repositories.dead_letter import SQLAlchemyDeadLetterRepository
    from kingsec.infrastructure.persistence.repositories.job_queue import SQLAlchemyJobQueueRepository
    from kingsec.infrastructure.persistence.repositories.lease import SQLAlchemyJobLeaseRepository
    from kingsec.infrastructure.persistence.repositories.worker import SQLAlchemyWorkerRepository

    def _make_worker_repo(_c: Any) -> WorkerRepositoryPort:
        return SQLAlchemyWorkerRepository(session_factory())

    def _make_queue_repo(_c: Any) -> JobQueueRepositoryPort:
        return SQLAlchemyJobQueueRepository(session_factory())

    def _make_lease_repo(_c: Any) -> JobLeaseRepositoryPort:
        return SQLAlchemyJobLeaseRepository(session_factory())

    def _make_dead_letter_repo(_c: Any) -> DeadLetterRepositoryPort:
        return SQLAlchemyDeadLetterRepository(session_factory())

    container.register_factory(WorkerRepositoryPort, _make_worker_repo)
    container.register_factory(JobQueueRepositoryPort, _make_queue_repo)
    container.register_factory(JobLeaseRepositoryPort, _make_lease_repo)
    container.register_factory(DeadLetterRepositoryPort, _make_dead_letter_repo)

    container.register_factory(
        WorkerRegistrationService,
        lambda c: WorkerRegistrationService(repo=c.resolve(WorkerRepositoryPort)),
    )

    container.register_factory(
        HeartbeatManager,
        lambda c: HeartbeatManager(
            worker_repo=c.resolve(WorkerRepositoryPort),
            job_queue_repo=c.resolve(JobQueueRepositoryPort),
            lease_repo=c.resolve(JobLeaseRepositoryPort),
            dead_letter_repo=c.resolve(DeadLetterRepositoryPort),
            heartbeat_timeout_seconds=30,
        ),
    )

    container.register_factory(
        JobLeaseManager,
        lambda c: JobLeaseManager(
            lease_repo=c.resolve(JobLeaseRepositoryPort),
            queue_repo=c.resolve(JobQueueRepositoryPort),
            ttl_seconds=120,
        ),
    )

    container.register_factory(
        JobDispatcher,
        lambda c: JobDispatcher(
            queue_repo=c.resolve(JobQueueRepositoryPort),
            worker_repo=c.resolve(WorkerRepositoryPort),
            lease_manager=c.resolve(JobLeaseManager),
            scheduler=CapabilityMatchingScheduler(),
            dead_letter_repo=c.resolve(DeadLetterRepositoryPort),
        ),
    )

    container.register_factory(
        RetryManager,
        lambda c: RetryManager(
            queue_repo=c.resolve(JobQueueRepositoryPort),
            dead_letter_repo=c.resolve(DeadLetterRepositoryPort),
            max_retries=3,
        ),
    )

    container.register_factory(
        DeadLetterService,
        lambda c: DeadLetterService(
            repo=c.resolve(DeadLetterRepositoryPort),
            queue_repo=c.resolve(JobQueueRepositoryPort),
        ),
    )


def _register_idp_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.idp.jit_provisioning import JITProvisioningService
    from kingsec.application.idp.ports import (
        AccountLinkRepositoryPort,
        IdentityProviderRepositoryPort,
        SSOSessionRepositoryPort,
    )
    from kingsec.application.idp.provider_service import IdentityProviderService
    from kingsec.application.idp.role_mapping_service import RoleMappingService
    from kingsec.application.ports.outbound import UserRepository
    from kingsec.infrastructure.persistence.repositories.identity import (
        SQLAlchemyAccountLinkRepository,
        SQLAlchemyIdentityProviderRepository,
        SQLAlchemySSOSessionRepository,
    )

    def _make_idp_repo(_c: Any) -> IdentityProviderRepositoryPort:
        return SQLAlchemyIdentityProviderRepository(session_factory())

    def _make_sso_session_repo(_c: Any) -> SSOSessionRepositoryPort:
        return SQLAlchemySSOSessionRepository(session_factory())

    def _make_account_link_repo(_c: Any) -> AccountLinkRepositoryPort:
        return SQLAlchemyAccountLinkRepository(session_factory())

    container.register_factory(IdentityProviderRepositoryPort, _make_idp_repo)
    container.register_factory(SSOSessionRepositoryPort, _make_sso_session_repo)
    container.register_factory(AccountLinkRepositoryPort, _make_account_link_repo)

    container.register_factory(
        IdentityProviderService,
        lambda c: IdentityProviderService(repo=c.resolve(IdentityProviderRepositoryPort)),
    )

    container.register_factory(
        RoleMappingService,
        lambda c: RoleMappingService(),
    )

    container.register_factory(
        JITProvisioningService,
        lambda c: JITProvisioningService(
            user_repo=c.resolve(UserRepository),
            account_link_repo=c.resolve(AccountLinkRepositoryPort),
            role_mapping=c.resolve(RoleMappingService),
        ),
    )


def _register_backup_services(container: Container, session_factory: Any) -> None:
    from kingsec.application.backup_service import BackupService
    from kingsec.application.ports.backup_service import BackupServicePort
    from kingsec.application.ports.outbound import (
        BackupCompressionPort,
        BackupEncryptionPort,
        BackupRepositoryPort,
        BackupStoragePort,
    )
    from kingsec.infrastructure.backup import (
        AESBackupEncryptionService,
        FilesystemBackupStorage,
        SQLAlchemyBackupRepository,
        ZipCompressionService,
        ensure_backup_tables,
    )
    from kingsec.infrastructure.config.models import AppSettings

    ensure_backup_tables(session_factory)

    def _make_backup_repo(_c: Any) -> BackupRepositoryPort:
        return SQLAlchemyBackupRepository(session_factory)

    def _make_backup_storage(_c: Any) -> BackupStoragePort:
        settings = _c.resolve(AppSettings) if _c.has(AppSettings) else None
        base = str(settings.storage.data_dir / "backups") if settings else "backups"
        return FilesystemBackupStorage(base)

    def _make_backup_encryption(_c: Any) -> BackupEncryptionPort:
        return AESBackupEncryptionService()

    def _make_backup_compression(_c: Any) -> BackupCompressionPort:
        return ZipCompressionService()

    container.register_factory(BackupRepositoryPort, _make_backup_repo)
    container.register_factory(BackupStoragePort, _make_backup_storage)
    container.register_factory(BackupEncryptionPort, _make_backup_encryption)
    container.register_factory(BackupCompressionPort, _make_backup_compression)

    container.register_factory(
        BackupServicePort,
        lambda c: BackupService(
            repo=c.resolve(BackupRepositoryPort),
            storage=c.resolve(BackupStoragePort),
            encryption=c.resolve(BackupEncryptionPort),
            compression=c.resolve(BackupCompressionPort),
            audit=c.resolve(AuditPublisher),
        ),
    )


def _register_performance_services(container: Container) -> None:
    """Register performance, caching, and metrics services."""
    from kingsec.infrastructure.cache.memory_cache import MemoryCacheService
    from kingsec.infrastructure.config.models import PerformanceSettings
    from kingsec.infrastructure.config.settings import Settings
    from kingsec.infrastructure.monitoring.performance_metrics import PerformanceMetrics

    # Register PerformanceSettings subgroup for DI resolution
    if not container.has(PerformanceSettings):
        root_settings = container.resolve(Settings)
        container.register_instance(PerformanceSettings, root_settings.performance)

    # Register in-memory cache (singleton)
    container.register_factory(
        MemoryCacheService,
        lambda c: MemoryCacheService(
            max_size=c.resolve(PerformanceSettings).cache_max_size,
            default_ttl=c.resolve(PerformanceSettings).cache_default_ttl,
        ),
    )

    # Register performance metrics (singleton)
    container.register_factory(
        PerformanceMetrics,
        lambda c: PerformanceMetrics(),
    )


def _register_production_services(container: Container, session_factory: Any) -> None:
    """Register ProductionService and all outbound port dependencies it needs."""
    from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
    from kingsec.application.ports.outbound.health_repository import HealthRepositoryPort
    from kingsec.application.ports.outbound.lifecycle_manager import LifecycleManagerPort
    from kingsec.application.ports.outbound.logging_port import LoggingPort
    from kingsec.application.ports.outbound.metrics_collector import MetricsCollectorPort
    from kingsec.application.ports.outbound.system_monitor import SystemMonitorPort
    from kingsec.application.ports.production_service import ProductionServicePort
    from kingsec.application.production_service import ProductionService
    from kingsec.infrastructure.production.health_checks import DatabaseHealthCheck
    from kingsec.infrastructure.production.in_memory_health_repo import InMemoryHealthRepository
    from kingsec.infrastructure.production.lifecycle import LifecycleManager
    from kingsec.infrastructure.production.logging_service import StructuredLogger
    from kingsec.infrastructure.production.metrics_collector import ProcessMetricsCollector
    from kingsec.infrastructure.production.monitor import SystemHealthMonitor

    if not container.has(SystemMonitorPort):
        db_check = DatabaseHealthCheck(session_factory=session_factory)
        container.register_factory(
            SystemMonitorPort,
            lambda c, _db=db_check: SystemHealthMonitor(db_check=_db),
        )

    if not container.has(MetricsCollectorPort):
        container.register_factory(
            MetricsCollectorPort,
            lambda c: ProcessMetricsCollector(),
        )

    if not container.has(HealthRepositoryPort):
        container.register_factory(
            HealthRepositoryPort,
            lambda c: InMemoryHealthRepository(),
        )

    if not container.has(LifecycleManagerPort):
        container.register_factory(
            LifecycleManagerPort,
            lambda c: LifecycleManager(),
        )

    if not container.has(LoggingPort):
        container.register_factory(
            LoggingPort,
            lambda c: StructuredLogger(),
        )

    if not container.has(ProductionService):
        _svc = ProductionService(
            monitor=container.resolve(SystemMonitorPort),
            collector=container.resolve(MetricsCollectorPort),
            repo=container.resolve(HealthRepositoryPort),
            lifecycle=container.resolve(LifecycleManagerPort),
            logger=container.resolve(LoggingPort),
            audit=container.resolve(AuditPublisher),
        )
        container.register_instance(ProductionService, _svc)
        container.register_instance(ProductionServicePort, _svc)


def _register_deployment_services(container: Container, settings: Any) -> None:
    """Register diagnostics, upgrade, release-audit and telemetry infrastructure."""
    from kingsec.infrastructure.audit.release_audit import ReleaseAuditService
    from kingsec.infrastructure.monitoring.diagnostics import DiagnosticsCollector
    from kingsec.infrastructure.telemetry.product_telemetry import ProductTelemetry
    from kingsec.infrastructure.upgrade.upgrade_service import UpgradeService

    data_dir = settings.storage.data_dir
    app_version = settings.app.version

    if not container.has(DiagnosticsCollector):
        container.register_factory(
            DiagnosticsCollector,
            lambda c: DiagnosticsCollector(data_dir=data_dir, app_version=app_version),
        )

    if not container.has(UpgradeService):
        container.register_factory(
            UpgradeService,
            lambda c: UpgradeService(data_dir=data_dir, current_version=app_version),
        )

    if not container.has(ReleaseAuditService):
        container.register_factory(
            ReleaseAuditService,
            lambda c: ReleaseAuditService(data_dir=data_dir),
        )

    if not container.has(ProductTelemetry):
        container.register_factory(
            ProductTelemetry,
            lambda c: ProductTelemetry(data_dir=data_dir),
        )
