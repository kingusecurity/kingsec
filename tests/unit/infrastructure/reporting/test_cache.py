"""Unit tests for ReportGeneratorAdapter's file cache (Phase 2B-c Priority 2, 5d).

Defect 5: /reports/{id}/download previously re-rendered the PDF from scratch
(WeasyPrint) on every single call. These tests use a StubRenderer that counts
invocations rather than real WeasyPrint, so a cache hit is provable directly
(call count) rather than inferred from timing.
"""

from __future__ import annotations

import dataclasses
import threading
from pathlib import Path

import pytest

from kingsec.infrastructure.reporting import ReportGeneratorAdapter
from kingsec.infrastructure.reporting.errors import ReportGenerationError
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

    def test_delete_for_assessment_removes_all_formats_and_snapshots_only_for_that_assessment(
        self, tmp_path: Path
    ) -> None:
        renderer = _CountingRenderer()
        adapter = ReportGeneratorAdapter(renderer, output_format="html", cache_dir=tmp_path)  # type: ignore[arg-type]
        report = build_report()
        regenerated = dataclasses.replace(report, generated_at=report.generated_at.replace(year=2027))

        adapter.render(report, format="html")
        adapter.render(regenerated, format="html")
        unrelated = tmp_path / "asmt-unrelated-1234567890abcdef.html"
        unrelated.write_bytes(b"keep")

        assert adapter.delete_for_assessment(report.assessment_id) == 2
        assert list(tmp_path.glob(f"{report.assessment_id}-*")) == []
        assert unrelated.read_bytes() == b"keep"

    def test_delete_for_assessment_does_not_match_a_longer_assessment_id(self, tmp_path: Path) -> None:
        renderer = _CountingRenderer()
        adapter = ReportGeneratorAdapter(renderer, output_format="html", cache_dir=tmp_path)  # type: ignore[arg-type]
        report = build_report()
        longer_id_report = dataclasses.replace(report, assessment_id=f"{report.assessment_id}-other")

        adapter.render(report, format="html")
        longer = adapter.render(longer_id_report, format="html")

        assert adapter.delete_for_assessment(report.assessment_id) == 1
        assert list(tmp_path.glob(f"{report.assessment_id}-*.html"))
        longer_cache = list(tmp_path.glob(f"{longer_id_report.assessment_id}-*.html"))
        assert len(longer_cache) == 1
        assert longer_cache[0].read_bytes() == longer.content

    def test_delete_for_assessment_wraps_unlink_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        adapter = ReportGeneratorAdapter(
            _CountingRenderer(), output_format="html", cache_dir=tmp_path  # type: ignore[arg-type]
        )
        report = build_report()
        adapter.render(report, format="html")
        cached = next(tmp_path.glob(f"{report.assessment_id}-*.html"))
        real_unlink = Path.unlink

        def refuse_unlink(path: Path, missing_ok: bool = False) -> None:
            if path == cached:
                raise PermissionError("simulated cache permission failure")
            real_unlink(path, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", refuse_unlink)

        with pytest.raises(ReportGenerationError) as exc_info:
            adapter.delete_for_assessment(report.assessment_id)

        assert exc_info.value.context == {
            "assessment_id": report.assessment_id,
            "error_type": "PermissionError",
        }
        assert "permission" not in str(exc_info.value).lower()
        assert cached.exists()

    def test_delete_for_assessment_without_cache_is_a_noop(self) -> None:
        adapter = ReportGeneratorAdapter(_CountingRenderer(), output_format="html")  # type: ignore[arg-type]
        assert adapter.delete_for_assessment("asmt-example") == 0

    def test_in_flight_render_cannot_recreate_cache_after_deletion(self, tmp_path: Path) -> None:
        started = threading.Event()
        release = threading.Event()
        failures: list[BaseException] = []

        class _BlockingRenderer(_CountingRenderer):
            def to_html(self, report) -> str:  # type: ignore[no-untyped-def]
                started.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("test did not release renderer")
                return super().to_html(report)

        adapter = ReportGeneratorAdapter(
            _BlockingRenderer(), output_format="html", cache_dir=tmp_path  # type: ignore[arg-type]
        )
        report = build_report()

        def render() -> None:
            try:
                adapter.render(report, format="html")
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        worker = threading.Thread(target=render)
        worker.start()
        assert started.wait(timeout=5), "render did not reach the controlled in-flight point"

        # No artifact exists yet, but deletion must still tombstone the id:
        # the renderer already holds a valid Report snapshot and will finish
        # only after cleanup returns.
        assert adapter.delete_for_assessment(report.assessment_id) == 0
        release.set()
        worker.join(timeout=5)

        assert not worker.is_alive()
        assert failures == []
        assert list(tmp_path.glob(f"{report.assessment_id}-*")) == []
