"""Unit tests for the renderer error translation and the adapter."""

from __future__ import annotations

import pytest

from kingsec.application import RenderedReport, ReportGeneratorPort
from kingsec.bootstrap import Container
from kingsec.infrastructure.reporting import (
    ReportGenerationError,
    ReportGeneratorAdapter,
    ReportRenderer,
    register_reporting,
)
from tests.unit.infrastructure.reporting.conftest import build_report


class TestRendererErrorTranslation:
    def test_html_error_becomes_report_error(self, monkeypatch) -> None:
        renderer = ReportRenderer()

        def boom(*_a, **_k):
            raise RuntimeError("template blew up")

        # Force the underlying template function to fail.
        monkeypatch.setattr(
            "kingsec.infrastructure.reporting.renderer.render_report_html", boom
        )
        with pytest.raises(ReportGenerationError):
            renderer.to_html(build_report())

    def test_pdf_library_error_becomes_report_error(self, monkeypatch) -> None:
        renderer = ReportRenderer()

        # Simulate the rendering library raising during PDF conversion. Patch the
        # library itself so the failure occurs at the real translation boundary.
        class _BadHTML:
            def __init__(self, *a, **k) -> None: ...

            def write_pdf(self, *a, **k):
                raise RuntimeError("weasy fail")

        monkeypatch.setattr("weasyprint.HTML", _BadHTML)
        with pytest.raises(ReportGenerationError):
            renderer.to_pdf(build_report())

    def test_no_library_exception_escapes(self, monkeypatch) -> None:
        renderer = ReportRenderer()

        class _BadHTML:
            def __init__(self, *a, **k) -> None: ...

            def write_pdf(self, *a, **k):
                raise ValueError("x")

        monkeypatch.setattr("weasyprint.HTML", _BadHTML)
        try:
            renderer.to_pdf(build_report())
        except ReportGenerationError:
            pass  # correct
        except Exception:  # pragma: no cover
            pytest.fail("a non-translated exception escaped the renderer")


class TestAdapter:
    def test_html_format_metadata(self) -> None:
        result = ReportGeneratorAdapter(output_format="html").render(build_report())
        assert isinstance(result, RenderedReport)
        assert result.media_type == "text/html; charset=utf-8"
        assert result.filename.endswith(".html")
        assert result.content.startswith(b"<!DOCTYPE html>")

    def test_returns_bytes_not_library_objects(self) -> None:
        result = ReportGeneratorAdapter(output_format="html").render(build_report())
        assert isinstance(result.content, bytes)

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ReportGenerationError, match="unsupported report format"):
            ReportGeneratorAdapter(output_format="docx")

    def test_uses_injected_renderer(self) -> None:
        class StubRenderer:
            def to_html(self, report):
                return "<!DOCTYPE html><html>stub</html>"

        adapter = ReportGeneratorAdapter(StubRenderer(), output_format="html")  # type: ignore[arg-type]
        assert b"stub" in adapter.render(build_report()).content


class TestDependencyInjection:
    def test_register_reporting_binds_port(self) -> None:
        container = Container()
        register_reporting(container, output_format="html")
        port = container.resolve(ReportGeneratorPort)
        assert isinstance(port, ReportGeneratorAdapter)
        assert port.render(build_report()).media_type.startswith("text/html")
