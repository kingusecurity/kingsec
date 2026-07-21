from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.infrastructure._container import ContainerProtocol

from .sqlalchemy_session_repository import SqlAlchemySessionRepository


def register_sessions(container: ContainerProtocol, session_factory: Callable[..., Any]) -> None:
    repo: SessionRepository = SqlAlchemySessionRepository(session_factory)
    container.register_instance(SessionRepository, repo)
