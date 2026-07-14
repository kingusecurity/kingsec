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
    AssessmentRepository,
    AuditPublisher,
    CancelAssessment,
    ChangePassword,
    CreateAssessment,
    DeleteAssessment,
    EventPublisher,
    GenerateReport,
    GetAssessment,
    JobRunner,
    ListAssessments,
    Login,
    PasswordHasher,
    RefreshToken,
    RegisterUser,
    ReportGeneratorPort,
    ReportRepository,
    ScannerPort,
    ServiceAPI,
    StartAssessment,
    SubmitAssessment,
    TokenService,
    UseCaseServiceAPI,
    UserRepository,
)
from kingsec.infrastructure.ai import register_ai
from kingsec.infrastructure.audit.provisioning import register_audit
from kingsec.infrastructure.auth.provisioning import register_auth, register_user_repository
from kingsec.infrastructure.events.provisioning import register_events
from kingsec.infrastructure.jobs import register_jobs
from kingsec.infrastructure.persistence import (
    create_session_factory,
    register_persistence,
    register_unit_of_work,
)
from kingsec.infrastructure.reporting import register_reporting
from kingsec.infrastructure.scanner import register_scanner

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

    # Audit trail: append-only persistence for security events.
    register_audit(container, session_factory)

    # Capability adapters. AI adds its own http-client.close shutdown hook.
    register_scanner(container, settings)
    register_ai(container, settings)
    register_reporting(container, output_format=report_format, brand_name=brand_name)
    register_jobs(container)
    register_events(container)


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
