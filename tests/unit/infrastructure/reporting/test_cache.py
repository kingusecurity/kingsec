"""Unit tests for ReportGeneratorAdapter's file cache (Phase 2B-c Priority 2, 5d).

Defect 5: /reports/{id}/download previously re-rendered the PDF from scratch
(WeasyPrint) on every single call. These tests use a StubRenderer that counts
invocations rather than real WeasyPrint, so a cache hit is provable directly
(call count) rather than inferred from timing.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from kingsec.infrastructure.reporting import ReportGeneratorAdapter
from tests.unit.infrastructure.reporting.conftest import build_report


class _CountingRenderer:
    def __init__(self) -> None:
        self.html_calls = 0

    def to_html(self, report):
        self.html_calls += 1
        return f"<!DOCTYPE html><html>render #{self.html_calls}</html>"

    def to_pdf(self, report):  # pragma: no cover - html-only in these tests
        raise NotImplementedError


class TestReportCache:
    def test_no_cache_dir_renders_every_call(self) -> None:
        renderer = _CountingRenderer()
        adapter = ReportGeneratorAdapter(renderer, output_format="html")  # type: ignore[arg-type]
        report = build_report()

        adapter.render(report)
        adapter.render(report)

        assert renderer.html_calls == 2

    def test_second_call_for_the_same_report_is_served_from_cache(self, tmp_path: Path) -> None:
        renderer = _CountingRenderer()
        adapter = ReportGeneratorAdapter(renderer, output_format="html", cache_dir=tmp_path)  # type: ignore[arg-type]
        report = build_report()

        first = adapter.render(report)
        second = adapter.render(report)

        assert renderer.html_calls == 1
        assert first.content == second.content
        assert second.content == b"<!DOCTYPE html><html>render #1</html>"

    def test_cache_writes_a_file_under_cache_dir(self, tmp_path: Path) -> None:
        renderer = _CountingRenderer()
        adapter = ReportGeneratorAdapter(renderer, output_format="html", cache_dir=tmp_path)  # type: ignore[arg-type]
        adapter.render(build_report())

        cached_files = list(tmp_path.glob("*.html"))
        assert len(cached_files) == 1

    def test_regenerated_report_gets_a_fresh_cache_entry_not_a_stale_hit(self, tmp_path: Path) -> None:
        # A new generated_at (regeneration) must never silently serve the
        # OLD snapshot's cached bytes - report content invalidates the cache.
        renderer = _CountingRenderer()
        adapter = ReportGeneratorAdapter(renderer, output_format="html", cache_dir=tmp_path)  # type: ignore[arg-type]
        report_v1 = build_report()
        report_v2 = dataclasses.replace(report_v1, generated_at=report_v1.generated_at.replace(year=2027))

        first = adapter.render(report_v1)
        second = adapter.render(report_v2)

        assert renderer.html_calls == 2
        assert first.content != second.content
        assert len(list(tmp_path.glob("*.html"))) == 2

    def test_different_format_for_the_same_report_is_not_a_cache_collision(self, tmp_path: Path) -> None:
        class _CountingBothFormats(_CountingRenderer):
            def __init__(self) -> None:
                super().__init__()
                self.pdf_calls = 0

            def to_pdf(self, report):
                self.pdf_calls += 1
                return b"%PDF-fake"

        renderer = _CountingBothFormats()
        adapter = ReportGeneratorAdapter(renderer, output_format="html", cache_dir=tmp_path)  # type: ignore[arg-type]
        report = build_report()

        adapter.render(report, format="html")
        adapter.render(report, format="pdf")

        assert renderer.html_calls == 1
        assert renderer.pdf_calls == 1
