"""Configuration and authorization security tests."""

from __future__ import annotations

import pytest

from kingsec.domain import Role


class TestSecretStrIntegration:
    """Verify that IntegrationSettings uses SecretStr for sensitive fields."""

    def test_webhook_secret_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.webhook_secret, SecretStr)

    def test_smtp_password_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.smtp_password, SecretStr)

    def test_jira_api_token_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.jira_api_token, SecretStr)

    def test_github_token_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.github_token, SecretStr)

    def test_gitlab_token_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.gitlab_token, SecretStr)

    def test_splunk_hec_token_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.splunk_hec_token, SecretStr)

    def test_sentinel_shared_key_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.sentinel_shared_key, SecretStr)

    def test_elastic_api_key_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings()
        assert isinstance(settings.elastic_api_key, SecretStr)

    def test_secrets_not_in_repr(self) -> None:
        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings(
            smtp_password="super-secret-password",
            jira_api_token="jira-token-123",
            github_token="ghp_secret123",
        )
        repr_str = repr(settings)
        assert "super-secret-password" not in repr_str
        assert "jira-token-123" not in repr_str
        assert "ghp_secret123" not in repr_str

    def test_secrets_masked_in_str(self) -> None:
        from kingsec.infrastructure.config.models import IntegrationSettings

        settings = IntegrationSettings(smtp_password="my-password")
        str_val = str(settings)
        assert "my-password" not in str_val


class TestPerformanceSettingsValidation:
    """Verify performance settings have safe bounds."""

    def test_cache_max_size_minimum(self) -> None:
        from kingsec.infrastructure.config.models import PerformanceSettings

        with pytest.raises(Exception):
            PerformanceSettings(cache_max_size=10)  # below minimum of 100

    def test_worker_count_maximum(self) -> None:
        from kingsec.infrastructure.config.models import PerformanceSettings

        with pytest.raises(Exception):
            PerformanceSettings(worker_count=100)  # above maximum of 64

    def test_request_timeout_bounds(self) -> None:
        from kingsec.infrastructure.config.models import PerformanceSettings

        with pytest.raises(Exception):
            PerformanceSettings(request_timeout=0.1)  # below minimum of 1.0

    def test_max_page_size_bounds(self) -> None:
        from kingsec.infrastructure.config.models import PerformanceSettings

        with pytest.raises(Exception):
            PerformanceSettings(max_page_size=5)  # below minimum of 10


class TestJWTSecurity:
    """Verify JWT security properties."""

    def test_jwt_secret_is_secretstr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import JWTSettings

        settings = JWTSettings()
        assert isinstance(settings.secret_key, SecretStr)

    def test_jwt_secret_not_in_repr(self) -> None:
        from pydantic import SecretStr

        from kingsec.infrastructure.config.models import JWTSettings

        settings = JWTSettings(secret_key=SecretStr("my-super-secret-key-1234567890abcdef"))
        repr_str = repr(settings)
        assert "my-super-secret-key" not in repr_str

    def test_access_token_expiration_bounded(self) -> None:
        from kingsec.infrastructure.config.models import JWTSettings

        settings = JWTSettings()
        assert 1 <= settings.access_token_expire_minutes <= 1440

    def test_refresh_token_expiration_bounded(self) -> None:
        from kingsec.infrastructure.config.models import JWTSettings

        settings = JWTSettings()
        assert 1 <= settings.refresh_token_expire_days <= 90


class TestPasswordHasherSecurity:
    """Verify password hashing security."""

    def test_argon2_used(self) -> None:
        from kingsec.infrastructure.auth.password_hasher import Argon2PasswordHasher

        hasher = Argon2PasswordHasher()
        password = "TestPassword123!"
        hashed = hasher.hash(password)
        assert hashed != password
        assert hasher.verify(password, hashed) is True

    def test_wrong_password_fails(self) -> None:
        from kingsec.infrastructure.auth.password_hasher import Argon2PasswordHasher

        hasher = Argon2PasswordHasher()
        hashed = hasher.hash("correct-password")
        assert hasher.verify("wrong-password", hashed) is False

    def test_different_hashes_for_same_password(self) -> None:
        from kingsec.infrastructure.auth.password_hasher import Argon2PasswordHasher

        hasher = Argon2PasswordHasher()
        h1 = hasher.hash("same-password")
        h2 = hasher.hash("same-password")
        # Salt should make them different
        assert h1 != h2


class TestRoleHierarchy:
    """Verify role hierarchy is enforced."""

    def test_admin_is_highest(self) -> None:
        assert Role.ADMIN.value > Role.ANALYST.value

    def test_viewer_is_lowest(self) -> None:
        assert Role.VIEWER.value < Role.ANALYST.value

    def test_all_roles_exist(self) -> None:
        roles = [Role.ADMIN, Role.ANALYST, Role.VIEWER]
        assert len(roles) == 3
