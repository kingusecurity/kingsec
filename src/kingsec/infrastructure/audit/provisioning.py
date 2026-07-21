"""DI wiring for audit trail infrastructure.

Registers the audit repository on the DI container. The composition root
calls ``register_audit()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.infrastructure._container import ContainerProtocol
from kingsec.infrastructure.persistence.audit_event_repository import SqlAlchemyAuditEventRepository
from kingsec.infrastructure.persistence.audit_repository import SqlAlchemyAuditRepository

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker


def register_audit(container: ContainerProtocol, session_factory: sessionmaker[Session]) -> None:
    """Register the audit repository on the container.

    Args:
        container: The DI container.
        session_factory: SQLAlchemy session factory (shared with other repos).
    """
    repo = SqlAlchemyAuditRepository(session_factory)
    container.register_instance(AuditPublisher, repo)


def register_enterprise_audit(container: ContainerProtocol, session_factory: sessionmaker[Session]) -> None:
    """Register the enterprise audit event repository on the container.

    Args:
        container: The DI container.
        session_factory: SQLAlchemy session factory (shared with other repos).
    """
    repo = SqlAlchemyAuditEventRepository(session_factory)
    container.register_instance(AuditEventRepository, repo)
