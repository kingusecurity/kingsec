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
    AIPort,
    ApiKeyHasher,
    ApiKeyRepository,
    AssessmentRepository,
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
    ListSchedules,
    ListSecrets,
    ListUserSessions,
    LockoutRepository,
    Login,
    MfaSecretRepository,
    PasswordHasher,
    PauseSchedule,
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
    engine = register_persistence(
        container, settings, validate_migrations=validate_migrations
    )
    session_factory = create_session_factory(engine)
    register_unit_of_work(container, session_factory)

    # Auth: password hasher + JWT token service + user repository.
    register_auth(container, settings)
    register_user_repository(container, session_factory)
    register_api_key_auth(container, session_factory, settings)

    # Audit trail: append-only persistence for security events.
    register_audit(container, session_factory)
    register_enterprise_audit(container, session_factory)

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
    register_reporting(container, output_format=report_format, brand_name=brand_name)
    register_jobs(container)
    register_events(container)


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
        lambda c: RefreshSession(c.resolve(SessionRepository)),
    )
    container.register_factory(
        RevokeSession,
        lambda c: RevokeSession(c.resolve(SessionRepository)),
    )
    container.register_factory(
        RevokeAllSessions,
        lambda c: RevokeAllSessions(c.resolve(SessionRepository)),
    )
    container.register_factory(
        ListUserSessions,
        lambda c: ListUserSessions(c.resolve(SessionRepository)),
    )
    container.register_factory(
        TerminateOtherSessions,
        lambda c: TerminateOtherSessions(c.resolve(SessionRepository)),
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
        lambda c: CheckAccountLockout(
            c.resolve(LockoutRepository), c.resolve(ClockPort)
        ),
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
