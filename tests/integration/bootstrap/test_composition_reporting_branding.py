"""Composition-root wiring for Phase 6 Task 6 report branding.

Proves settings.reporting.brand_name has a real, tested effect on the REAL
composition root (create_wired_application()) - not a setting that exists
but nothing reads, the same class of defect this engagement has found and
closed before (see docs/STATUS.md's backlog for the settings that don't).
Same methodology as test_composition_authorization_scope.py: build through
the real container, set the env var, resolve the real port, and check the
real rendered output - not a unit test on the settings object alone.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

from cryptography.fernet import Fernet

from kingsec.application.ports import ReportGeneratorPort
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Assessment, Authorization, Report, Target, TargetType
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


def _build_app(tmp_path, monkeypatch, *, brand_name: str | None):
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    if brand_name is not None:
        monkeypatch.setenv("KINGSEC_REPORTING__BRAND_NAME", brand_name)
    engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
    create_schema(engine)
    engine.dispose()
    return create_wired_application(
        log_stream=io.StringIO(),
        ensure_directories=False,
        validate_migrations=False,
    )


def _real_report() -> Report:
    """A minimal, real domain Report - not a mock, not a fixture stub."""
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", datetime.now(UTC), scope="10.0.0.5"))
    assessment.start()
    assessment.complete()
    return Report.from_assessment(assessment)


class TestReportingBrandNameSetting:
    def test_configured_brand_name_reaches_the_real_rendered_report(self, tmp_path, monkeypatch) -> None:
        """The whole point of Task 6: an operator sets one env var and the
        real, unmodified report-generation path picks it up - resolved
        through create_wired_application()'s own real DI container, the
        exact path the live `kingsec` server uses, not a hand-built
        ReportRenderer instantiated directly in the test."""
        app = _build_app(tmp_path, monkeypatch, brand_name="AcmeSec Assessments")
        generator = app.container.resolve(ReportGeneratorPort)

        rendered = generator.render(_real_report(), format="html")
        html = rendered.content.decode("utf-8")

        assert "AcmeSec Assessments" in html
        assert "KingSec" not in html  # the configured value fully replaces the hardcoded default

    def test_unconfigured_falls_back_to_the_real_default(self, tmp_path, monkeypatch) -> None:
        """No env var set - must resolve to ReportingSettings.brand_name's
        own default ("KingSec"), not an empty string or an error."""
        app = _build_app(tmp_path, monkeypatch, brand_name=None)
        generator = app.container.resolve(ReportGeneratorPort)

        rendered = generator.render(_real_report(), format="html")
        html = rendered.content.decode("utf-8")

        assert "KingSec" in html

    def test_explicit_create_wired_application_arg_still_overrides(self, tmp_path, monkeypatch) -> None:
        """An explicit brand_name= kwarg to create_wired_application() must
        still win over the env var - scripts/tests that need a specific
        value regardless of configuration keep working."""
        monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
        monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
        monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
        monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
        monkeypatch.setenv("KINGSEC_REPORTING__BRAND_NAME", "FromEnvVar")
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
        create_schema(engine)
        engine.dispose()
        app = create_wired_application(
            log_stream=io.StringIO(),
            ensure_directories=False,
            validate_migrations=False,
            brand_name="ExplicitOverride",
        )
        generator = app.container.resolve(ReportGeneratorPort)

        rendered = generator.render(_real_report(), format="html")
        html = rendered.content.decode("utf-8")

        assert "ExplicitOverride" in html
        assert "FromEnvVar" not in html
