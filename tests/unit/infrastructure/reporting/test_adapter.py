"""Unit tests for the renderer error translation and the adapter."""

from __future__ import annotations

import sys
import types

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


def _inject_fake_weasyprint(monkeypatch, *, write_pdf_exc: Exception | None = None):
    """Inject a fake weasyprint module so the renderer's lazy import succeeds.

    The fake ``HTML`` class either raises ``write_pdf_exc`` from ``write_pdf``
    (if provided) or returns a minimal bytes object.
    """
    fake_module = types.ModuleType("weasyprint")

    class _FakeHTML:
        def __init__(self, *a, **k) -> None: ...

        def write_pdf(self, *a, **k):
            if write_pdf_exc is not None:
                raise write_pdf_exc
            return b"%PDF-fake"

    fake_module.HTML = _FakeHTML  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "weasyprint", fake_module)


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
        _inject_fake_weasyprint(monkeypatch, write_pdf_exc=RuntimeError("weasy fail"))
        with pytest.raises(ReportGenerationError):
            renderer.to_pdf(build_report())

    def test_no_library_exception_escapes(self, monkeypatch) -> None:
        renderer = ReportRenderer()
        _inject_fake_weasyprint(monkeypatch, write_pdf_exc=ValueError("x"))
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
