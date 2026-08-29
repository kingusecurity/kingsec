"""DI wiring for authentication infrastructure.

Registers the password hasher, JWT token service, and user repository
on the DI container. The composition root calls ``register_auth()``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kingsec.application.ports import (
    ApiKeyHasher,
    ApiKeyRepository,
    PasswordHasher,
    TokenService,
    UserRepository,
)
from kingsec.infrastructure._container import ContainerProtocol
from kingsec.infrastructure.config.errors import ConfigError
from kingsec.infrastructure.config.models import DEFAULT_SECRET_PLACEHOLDER
from kingsec.infrastructure.config.settings import Settings
from kingsec.infrastructure.persistence.user_repository import SqlAlchemyUserRepository

from .jwt_service import JWTTokenService


def register_auth(
    container: ContainerProtocol, settings: Settings, session_factory: Callable[..., Any] | None = None
) -> None:
    """Register authentication adapters on the container.

    Args:
        container: The DI container.
        settings: Application settings (contains jwt.* config).
        session_factory: Optional SQLAlchemy session factory for persistent token revocation.

    Raises:
        ConfigError: If the JWT signing secret is still the repository's
            literal example placeholder. ``Settings``'s own production guard
            (see ``config.settings``) only rejects this value when
            ``environment=production``; a real ``JWTTokenService`` capable of
            signing tokens must never be built from a publicly-known secret
            in *any* environment, so this check runs unconditionally here at
            the composition root instead.
        ConfigError: If the JWT signing secret is empty. This is not an
            arbitrary minimum-length policy (production's own 32-byte
            minimum is untouched and non-production still allows short
            synthetic secrets) - it is specific to the one value PyJWT
            itself refuses to sign with (``InvalidKeyError: HMAC key must
            not be empty``, confirmed by direct testing). Without this
            check, ``Settings()``/``create_wired_application()`` both
            construct successfully and the failure only surfaces the first
            time anything tries to issue a token - a startup that looks
            healthy but is unusable for authentication.
    """
    from .password_hasher import Argon2PasswordHasher

    hasher = Argon2PasswordHasher()
    container.register_instance(PasswordHasher, hasher)

    jwt_secret = settings.jwt.secret_key.get_secret_value()
    if jwt_secret == DEFAULT_SECRET_PLACEHOLDER:
        raise ConfigError(
            "KINGSEC_JWT__SECRET_KEY is still set to the insecure default placeholder. "
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    if not jwt_secret:
        raise ConfigError(
            "KINGSEC_JWT__SECRET_KEY is empty. A JWT signing key cannot be empty - "
            'generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    jwt_service = JWTTokenService(settings.jwt, session_factory=session_factory)
    container.register_instance(TokenService, jwt_service)


def register_user_repository(container: ContainerProtocol, session_factory: Callable[..., Any]) -> None:
    """Register the user repository on the container.

    Args:
        container: The DI container.
        session_factory: SQLAlchemy session factory.
    """
    repo = SqlAlchemyUserRepository(session_factory)
    container.register_instance(UserRepository, repo)


def register_api_key_auth(
    container: ContainerProtocol, session_factory: Callable[..., Any], settings: Settings | None = None
) -> None:
    """Register API key hasher and repository on the container.

    Args:
        container: The DI container.
        session_factory: SQLAlchemy session factory.
        settings: Application settings (contains secrets.* config).

    Raises:
        ConfigError: If ``settings`` is provided and its API key pepper is
            still the repository's literal example placeholder. Mirrors
            ``register_auth()``'s unconditional JWT-secret check: a pepper
            used to hash real API keys must never be the publicly-known
            placeholder in any environment. Only checked when ``settings``
            is supplied, matching this function's existing settings-optional
            signature.
        ConfigError: If ``settings`` is provided and its API key pepper is
            empty. ``HmacApiKeyHasher`` already refuses an empty pepper
            (``ValueError``); this re-raises that as a ``ConfigError`` naming
            the environment variable and a fix, matching every other
            secret-related startup error in this codebase, instead of a bare
            ``ValueError`` with no variable name or remediation.
    """
    from kingsec.infrastructure.persistence.api_key_repository import SqlAlchemyApiKeyRepository

    from .api_key_hasher import HmacApiKeyHasher

    pepper = settings.secrets.api_key_pepper.get_secret_value() if settings else DEFAULT_SECRET_PLACEHOLDER
    if settings is not None and pepper == DEFAULT_SECRET_PLACEHOLDER:
        raise ConfigError(
            "KINGSEC_SECRETS__API_KEY_PEPPER is still set to the insecure default placeholder. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    if settings is not None and not pepper:
        raise ConfigError(
            "KINGSEC_SECRETS__API_KEY_PEPPER is empty. A pepper cannot be empty - "
            'generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    hasher = HmacApiKeyHasher(pepper)
    container.register_instance(ApiKeyHasher, hasher)

    repo = SqlAlchemyApiKeyRepository(session_factory)
    container.register_instance(ApiKeyRepository, repo)
