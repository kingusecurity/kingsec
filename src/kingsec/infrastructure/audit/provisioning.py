"""DI wiring for audit trail infrastructure.

Registers the audit repository on the DI container. The composition root
calls ``register_audit()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.bootstrap.container import Container
from kingsec.infrastructure.persistence.audit_repository import SqlAlchemyAuditRepository

if TYPE_CHECKING:
    from sqlalchemy.orm import sessionmaker


def register_audit(container: Container, session_factory: sessionmaker) -> None:
    """Register the audit repository on the container.

    Args:
        container: The DI container.
        session_factory: SQLAlchemy session factory (shared with other repos).
    """
    repo = SqlAlchemyAuditRepository(session_factory)
    container.register_instance(AuditPublisher, repo)
