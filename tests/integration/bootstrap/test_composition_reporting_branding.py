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

import builtins
import io
import json
from datetime import UTC, datetime

from cryptography.fernet import Fernet

from kingsec.application import GenerateReport, GenerateReportRequest
from kingsec.application.ports import AssessmentRepository, ReportGeneratorPort
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Assessment, Authorization, Report, Target, TargetType
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


def _build_app(tmp_path, monkeypatch, *, brand_name: str | None, report_format: str | None = None):
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    if brand_name is not None:
        monkeypatch.setenv("KINGSEC_REPORTING__BRAND_NAME", brand_name)
    if report_format is not None:
        monkeypatch.setenv("KINGSEC_REPORTING__REPORT_FORMAT", report_format)
    engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
    create_schema(engine)
    engine.dispose()
    return create_wired_application(
        log_stream=io.StringIO(),
        ensure_directories=False,
        validate_migrations=False,
    )


def _real_completed_assessment() -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", datetime.now(UTC), scope="10.0.0.5"))
    assessment.start()
    assessment.complete()
    return assessment


def _real_report() -> Report:
    """A minimal, real domain Report - not a mock, not a fixture stub."""
    return Report.from_assessment(_real_completed_assessment())


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


class TestReportingFormatSetting:
    def test_configured_html_is_the_real_default_without_weasyprint(self, tmp_path, monkeypatch) -> None:
        real_import = builtins.__import__

        def reject_weasyprint(name, *args, **kwargs):
            if name == "weasyprint" or name.startswith("weasyprint."):
                raise OSError("GTK/Pango unavailable")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", reject_weasyprint)
        app = _build_app(tmp_path, monkeypatch, brand_name=None, report_format="html")
        assessment = _real_completed_assessment()
        app.resolve(AssessmentRepository).save(assessment)

        rendered = app.resolve(GenerateReport).execute(
            GenerateReportRequest(str(assessment.id), requesting_user="tester", is_admin=True)
        )

        assert rendered.artifact_media_type == "text/html; charset=utf-8"
        assert rendered.artifact_filename.endswith(".html")
        assert rendered.artifact_bytes > 1000

    def test_explicit_format_argument_overrides_the_environment(self, tmp_path, monkeypatch) -> None:
        app = _build_app(tmp_path, monkeypatch, brand_name=None, report_format="html")
        explicit = create_wired_application(
            log_stream=io.StringIO(),
            ensure_directories=False,
            validate_migrations=False,
            report_format="pdf",
        )

        assert app.settings.reporting.report_format == "html"
        generator = explicit.container.resolve(ReportGeneratorPort)
        assert vars(generator)["_format"] == "pdf"

    def test_composition_log_uses_the_resolved_format(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
        monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
        monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
        monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
        monkeypatch.setenv("KINGSEC_REPORTING__REPORT_FORMAT", "html")
        monkeypatch.setenv("KINGSEC_LOGGING__JSON_FORMAT", "true")
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
        create_schema(engine)
        engine.dispose()
        stream = io.StringIO()

        create_wired_application(
            log_stream=stream,
            ensure_directories=False,
            validate_migrations=False,
        )

        events = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
        composed = next(event for event in events if event.get("event") == "application composed")
        assert composed["report_format"] == "html"
