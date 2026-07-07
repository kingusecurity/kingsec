"""Dependency-injection wiring for persistence.

``register_persistence`` plugs the SQLite adapters into the Module 2.4 container.
It accepts the container via a structural ``Protocol`` rather than importing the
concrete ``Container`` class, so infrastructure never depends on the bootstrap
(composition-root) layer — only on an abstract capability. The real 2.4
``Container`` satisfies this Protocol automatically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Protocol

from sqlalchemy import Engine

from kingsec.application import AssessmentRepository, ReportRepository
from kingsec.infrastructure.logging import get_logger

from .database import create_database_engine, create_schema, create_session_factory
from .repositories import SqlAlchemyAssessmentRepository, SqlAlchemyReportRepository

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
    settings: "Settings",
    *,
    engine: Engine | None = None,
) -> Engine:
    """Create the engine/schema and register repositories on the container.

    Binds the port types (``AssessmentRepository``, ``ReportRepository``) to their
    SQLite implementations, and registers ``engine.dispose`` as a shutdown hook so
    the connection pool is released cleanly when the application stops.

    Args:
        container: The bootstrap DI container (structurally typed).
        settings: Application settings used to locate the SQLite database.
        engine: An optional pre-built engine (useful for tests). If omitted, one
            is created from ``settings``.

    Returns:
        The engine that was created/used, for the caller's reference.
    """

    engine = engine or create_database_engine(settings=settings)
    create_schema(engine)
    session_factory = create_session_factory(engine)

    container.register_instance(
        AssessmentRepository, SqlAlchemyAssessmentRepository(session_factory)
    )
    container.register_instance(
        ReportRepository, SqlAlchemyReportRepository(session_factory)
    )
    # Connection lifecycle: dispose the pool on shutdown (runs LIFO).
    container.add_shutdown_hook(engine.dispose)

    _logger.info("persistence registered", backend="sqlite")
    return engine
