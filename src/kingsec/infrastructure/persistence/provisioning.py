"""Dependency-injection wiring for persistence.

``register_persistence`` plugs the SQLite adapters into the Module 2.4 container.
It accepts the container via a structural ``Protocol`` rather than importing the
concrete ``Container`` class, so infrastructure never depends on the bootstrap
(composition-root) layer — only on an abstract capability. The real 2.4
``Container`` satisfies this Protocol automatically.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy import Engine

from kingsec.application import AssessmentRepository, ReportRepository
from kingsec.application.ports import AuthorizationGrantRepository
from kingsec.application.ports.outbound.assessment_concurrency import AssessmentConcurrencyPort
from kingsec.infrastructure.logging import get_logger

from .database import create_database_engine, create_session_factory, validate_schema_version
from .repositories import LegacyAssessmentRepository, LegacyAuthorizationGrantRepository, LegacyReportRepository
from .repositories.assessment_concurrency import SqlAlchemyAssessmentConcurrencyRepository

if TYPE_CHECKING:  # typing only
    from kingsec.infrastructure.config import Settings

_logger = get_logger("kingsec.infrastructure.persistence")


class ServiceContainer(Protocol):
    """The subset of the bootstrap container that persistence needs.

    Declaring this structurally keeps infrastructure decoupled from the concrete
    ``Container`` in the bootstrap layer while still integrating with it.
    """

    def register_instance(self, service_type: type, instance: Any) -> None: ...

    def add_shutdown_hook(self, hook: Callable[[], None]) -> None: ...


def register_persistence(
    container: ServiceContainer,
    settings: Settings,
    *,
    engine: Engine | None = None,
    validate_migrations: bool = True,
) -> Engine:
    """Create the engine, optionally validate migrations, and register repositories.

    In production (``validate_migrations=True``), the database MUST already be
    migrated via ``alembic upgrade head``. This function validates that the
    ``alembic_version`` table exists and has a recorded version; if not, it
    raises ``RuntimeError`` with remediation instructions.

    In tests (``validate_migrations=False``), schema creation via
    ``create_schema(engine)`` should be called before this function. This
    skips the Alembic version check.

    Args:
        container: The bootstrap DI container (structurally typed).
        settings: Application settings used to locate the SQLite database.
        engine: An optional pre-built engine (useful for tests). If omitted, one
            is created from ``settings``.
        validate_migrations: Whether to verify the Alembic version table.
            Pass ``False`` in tests that use ``create_schema()`` directly.

    Returns:
        The engine that was created/used, for the caller's reference.

    Raises:
        RuntimeError: If ``validate_migrations`` is True and the database has
            not been migrated via Alembic.
    """
    engine = engine or create_database_engine(settings=settings)
    if validate_migrations:
        validate_schema_version(engine)
    session_factory = create_session_factory(engine)

    container.register_instance(AssessmentRepository, LegacyAssessmentRepository(session_factory))
    container.register_instance(ReportRepository, LegacyReportRepository(session_factory))
    # Phase 4 (authorization scope enforcement): registered unconditionally -
    # whether CreateAssessment actually RECEIVES this depends on
    # settings.security.enforce_authorization_scope, decided in
    # composition.py's _register_use_cases(), not here. This function's
    # job is only "is a real adapter available", never a policy decision.
    container.register_instance(AuthorizationGrantRepository, LegacyAuthorizationGrantRepository(session_factory))
    # KSEC-87-02: same session_factory/engine as everything else here - the
    # concurrency-slot table lives in the same database, so its atomic
    # UPDATEs participate in the same SQLite write-serialization as every
    # other write.
    container.register_instance(
        AssessmentConcurrencyPort, SqlAlchemyAssessmentConcurrencyRepository(session_factory)
    )
    # Connection lifecycle: dispose the pool on shutdown (runs LIFO).
    container.add_shutdown_hook(engine.dispose)

    _logger.info("persistence registered", backend="sqlite")
    return engine
