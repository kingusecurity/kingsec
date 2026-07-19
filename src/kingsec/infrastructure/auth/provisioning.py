"""DI wiring for authentication infrastructure.

Registers the password hasher, JWT token service, and user repository
on the DI container. The composition root calls ``register_auth()``.
"""

from __future__ import annotations

from kingsec.application.ports import PasswordHasher, TokenService, UserRepository
from kingsec.infrastructure.config.settings import Settings

from ..persistence.user_repository import SqlAlchemyUserRepository
from .jwt_service import JWTTokenService


def register_auth(container: object, settings: Settings) -> None:
    """Register authentication adapters on the container.

    Args:
        container: The DI container.
        settings: Application settings (contains jwt.* config).
    """
    from .password_hasher import Argon2PasswordHasher

    hasher = Argon2PasswordHasher()
    container.register_instance(PasswordHasher, hasher)

    jwt_service = JWTTokenService(settings.jwt)
    container.register_instance(TokenService, jwt_service)


def register_user_repository(container: object, session_factory: callable) -> None:
    """Register the user repository on the container.

    Args:
        container: The DI container.
        session_factory: SQLAlchemy session factory.
    """
    repo = SqlAlchemyUserRepository(session_factory)
    container.register_instance(UserRepository, repo)
