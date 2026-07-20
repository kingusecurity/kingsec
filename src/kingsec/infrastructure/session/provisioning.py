from __future__ import annotations

from kingsec.application.ports.outbound.session_repository import SessionRepository

from .sqlalchemy_session_repository import SqlAlchemySessionRepository


def register_sessions(container: object, session_factory: callable) -> None:
    repo: SessionRepository = SqlAlchemySessionRepository(session_factory)
    container.register_instance(SessionRepository, repo)
