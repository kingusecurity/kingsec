"""Phase 25: register_auth()/register_api_key_auth() must reject the
repository's literal placeholder JWT secret/API-key pepper in every
environment, not just production.

``Settings._guard_default_secrets_in_production()`` (see
``infrastructure.config.settings``) only rejects the placeholder when
``environment=production``. That leaves a real, signing-capable
``JWTTokenService``/``HmacApiKeyHasher`` buildable from the publicly-known
placeholder in every other environment (development, testing) - the exact
gap Phase 25 Objective 3 closes. These tests exercise the provisioning
functions directly, independent of environment, to prove the fix and
guard against regression.

Phase 26 adds: an empty JWT secret/pepper is also rejected here, in every
environment. This is not an arbitrary minimum-length policy (production's
own 32-byte minimum in ``settings.py`` is untouched, and a short synthetic
secret like ``"a-real-generated-dev-secret"`` above is still accepted) - it
specifically targets the one degenerate value PyJWT itself refuses to sign
with (confirmed by direct testing: ``jwt.encode(..., "", algorithm="HS256")``
raises ``InvalidKeyError: HMAC key must not be empty``). Before this fix,
``Settings()``/``create_wired_application()`` both constructed successfully
with an empty secret, and the failure only surfaced the first time anything
tried to issue a token - a startup that looked healthy but was unusable for
authentication.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from kingsec.application.ports import ApiKeyHasher, TokenService
from kingsec.infrastructure.auth.provisioning import register_api_key_auth, register_auth
from kingsec.infrastructure.config.errors import ConfigError
from kingsec.infrastructure.config.models import DEFAULT_SECRET_PLACEHOLDER
from kingsec.infrastructure.config.settings import Settings


class _FakeContainer:
    """Minimal ``ContainerProtocol`` double: just records what was registered."""

    def __init__(self) -> None:
        self.instances: dict[type[Any], Any] = {}

    def register_instance(self, service_type: type[Any], instance: Any) -> None:
        self.instances[service_type] = instance

    def add_shutdown_hook(self, hook: Callable[[], None]) -> None:
        pass

    def resolve(self, service_type: type[Any]) -> Any:
        return self.instances[service_type]


def _settings(monkeypatch: pytest.MonkeyPatch, *, jwt_secret: str, pepper: str, environment: str = "development") -> Settings:
    # Explicit env vars beat any real .env in the working directory (see
    # settings.py's own documented precedence), so this is deterministic
    # regardless of what a developer's local .env happens to contain.
    monkeypatch.setenv("KINGSEC_APP__ENVIRONMENT", environment)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", jwt_secret)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", pepper)
    return Settings()


class TestRegisterAuthRejectsPlaceholder:
    def test_placeholder_jwt_secret_rejected_in_development(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(
            monkeypatch, jwt_secret=DEFAULT_SECRET_PLACEHOLDER, pepper="a-real-generated-pepper-value", environment="development"
        )
        with pytest.raises(ConfigError) as excinfo:
            register_auth(_FakeContainer(), settings)
        message = str(excinfo.value)
        assert "KINGSEC_JWT__SECRET_KEY" in message
        # The error must name the problem and how to fix it, never the value.
        assert DEFAULT_SECRET_PLACEHOLDER not in message

    def test_placeholder_jwt_secret_rejected_in_testing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(
            monkeypatch, jwt_secret=DEFAULT_SECRET_PLACEHOLDER, pepper="a-real-generated-pepper-value", environment="testing"
        )
        with pytest.raises(ConfigError):
            register_auth(_FakeContainer(), settings)

    def test_generated_dev_secret_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(
            monkeypatch, jwt_secret="a-real-generated-dev-secret", pepper="a-real-generated-pepper-value", environment="development"
        )
        container = _FakeContainer()
        register_auth(container, settings)  # must not raise
        assert container.resolve(TokenService) is not None

    def test_nothing_registered_when_placeholder_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A rejected placeholder must abort before any signing service is
        # wired - never construct-then-discard a live JWTTokenService.
        settings = _settings(
            monkeypatch, jwt_secret=DEFAULT_SECRET_PLACEHOLDER, pepper="a-real-generated-pepper-value", environment="development"
        )
        container = _FakeContainer()
        with pytest.raises(ConfigError):
            register_auth(container, settings)
        assert TokenService not in container.instances


class TestRegisterAuthRejectsEmptySecret:
    """Phase 26: an empty JWT secret is a confirmed defect, not a style
    preference - PyJWT itself refuses to sign with it (see module docstring).
    """

    @pytest.mark.parametrize("environment", ["development", "testing"])
    def test_empty_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch, environment: str) -> None:
        settings = _settings(monkeypatch, jwt_secret="", pepper="a-real-generated-pepper-value", environment=environment)
        with pytest.raises(ConfigError) as excinfo:
            register_auth(_FakeContainer(), settings)
        message = str(excinfo.value)
        assert "KINGSEC_JWT__SECRET_KEY" in message
        assert "empty" in message.lower()

    def test_nothing_registered_when_empty_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(monkeypatch, jwt_secret="", pepper="a-real-generated-pepper-value", environment="development")
        container = _FakeContainer()
        with pytest.raises(ConfigError):
            register_auth(container, settings)
        assert TokenService not in container.instances

    def test_short_but_nonempty_dev_secret_still_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The fix targets emptiness specifically, not a minimum length -
        # short synthetic secrets remain a valid non-production convenience
        # (see test_generated_dev_secret_is_accepted above; this test pins
        # a much shorter value to make that boundary explicit).
        settings = _settings(monkeypatch, jwt_secret="x", pepper="a-real-generated-pepper-value", environment="development")
        container = _FakeContainer()
        register_auth(container, settings)  # must not raise
        assert container.resolve(TokenService) is not None


class TestRegisterApiKeyAuthRejectsPlaceholder:
    def test_placeholder_pepper_rejected_in_development(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(
            monkeypatch, jwt_secret="a-real-generated-dev-secret", pepper=DEFAULT_SECRET_PLACEHOLDER, environment="development"
        )
        with pytest.raises(ConfigError) as excinfo:
            register_api_key_auth(_FakeContainer(), session_factory=lambda: None, settings=settings)
        message = str(excinfo.value)
        assert "KINGSEC_SECRETS__API_KEY_PEPPER" in message
        assert DEFAULT_SECRET_PLACEHOLDER not in message

    def test_generated_dev_pepper_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(
            monkeypatch, jwt_secret="a-real-generated-dev-secret", pepper="a-real-generated-pepper-value", environment="development"
        )
        container = _FakeContainer()
        register_api_key_auth(container, session_factory=lambda: None, settings=settings)  # must not raise
        assert container.resolve(ApiKeyHasher) is not None

    def test_settings_none_still_supported(self) -> None:
        # register_api_key_auth's settings parameter is optional (used by a
        # couple of lightweight call sites); Phase 25 must not force a
        # settings object where none was required before.
        container = _FakeContainer()
        register_api_key_auth(container, session_factory=lambda: None, settings=None)  # must not raise
        assert container.resolve(ApiKeyHasher) is not None


class TestRegisterApiKeyAuthRejectsEmptyPepper:
    """Phase 26: HmacApiKeyHasher already refused an empty pepper (raw
    ValueError); this proves it now surfaces as a ConfigError naming the
    environment variable, matching every other secret-related startup error.
    """

    def test_empty_pepper_rejected_as_config_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(monkeypatch, jwt_secret="a-real-generated-dev-secret", pepper="", environment="development")
        with pytest.raises(ConfigError) as excinfo:
            register_api_key_auth(_FakeContainer(), session_factory=lambda: None, settings=settings)
        message = str(excinfo.value)
        assert "KINGSEC_SECRETS__API_KEY_PEPPER" in message
        assert "empty" in message.lower()

    def test_nothing_registered_when_empty_pepper_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(monkeypatch, jwt_secret="a-real-generated-dev-secret", pepper="", environment="development")
        container = _FakeContainer()
        with pytest.raises(ConfigError):
            register_api_key_auth(container, session_factory=lambda: None, settings=settings)
        assert ApiKeyHasher not in container.instances
