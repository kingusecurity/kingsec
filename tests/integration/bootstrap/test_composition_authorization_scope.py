"""Composition-root wiring for Phase 4 authorization scope enforcement.

Proves settings.security.enforce_authorization_scope has a real, tested
effect on the REAL composition root (create_wired_application()), in both
directions - not a phantom setting like the deleted require_authorization,
whose docstring described a gate that wired nothing.
"""

from __future__ import annotations

import io

from cryptography.fernet import Fernet

from kingsec.application import CreateAssessment
from kingsec.application.ports import AuthorizationGrantRepository
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.bootstrap.composition import create_wired_application
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


def _build_app(tmp_path, monkeypatch, *, enforce: bool):
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    monkeypatch.setenv("KINGSEC_SECURITY__ENFORCE_AUTHORIZATION_SCOPE", "true" if enforce else "false")
    engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
    create_schema(engine)
    engine.dispose()
    return create_wired_application(
        log_stream=io.StringIO(),
        ensure_directories=False,
        validate_migrations=False,
    )


class TestEnforceAuthorizationScopeFlag:
    def test_true_wires_real_dependencies_into_create_assessment(self, tmp_path, monkeypatch) -> None:
        app = _build_app(tmp_path, monkeypatch, enforce=True)
        create_assessment = app.container.resolve(CreateAssessment)

        assert create_assessment._grants is not None
        assert create_assessment._registry is not None
        assert create_assessment._planner is not None
        assert isinstance(create_assessment._grants, AuthorizationGrantRepository)
        assert isinstance(create_assessment._registry, ScannerPluginRegistry)

    def test_false_disables_grant_enforcement_but_keeps_profile_validation(
        self, tmp_path, monkeypatch
    ) -> None:
        app = _build_app(tmp_path, monkeypatch, enforce=False)
        create_assessment = app.container.resolve(CreateAssessment)

        assert create_assessment._grants is None
        assert create_assessment._registry is None
        assert create_assessment._planner is not None

    def test_authorization_grant_repository_itself_is_always_registered(self, tmp_path, monkeypatch) -> None:
        """Registered unconditionally by provisioning.py regardless of the
        flag - the flag decides what CreateAssessment receives, not
        whether the adapter exists at all (needed independently by the
        authorization-grants route's own use cases)."""
        app = _build_app(tmp_path, monkeypatch, enforce=False)
        # Does not raise - the port resolves to a real adapter either way.
        app.container.resolve(AuthorizationGrantRepository)
