"""Correlation / assessment context binding."""

from __future__ import annotations

from collections.abc import Callable

from kingsec.infrastructure.logging import (
    bind_assessment_id,
    bind_correlation_id,
    get_logger,
    logging_context,
)


class TestCorrelationId:
    def test_bound_correlation_id_appears_on_lines(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        cid = bind_correlation_id("fixed-cid-123")
        get_logger("kingsec.test").info("with cid")

        (line,) = read_json()
        assert cid == "fixed-cid-123"
        assert line["correlation_id"] == "fixed-cid-123"

    def test_generated_correlation_id_is_returned(self) -> None:
        cid = bind_correlation_id()
        assert isinstance(cid, str)
        assert len(cid) == 32  # uuid4().hex


class TestAssessmentId:
    def test_assessment_id_appears_on_lines(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        bind_assessment_id("assessment-42")
        get_logger("kingsec.test").info("scanning")

        (line,) = read_json()
        assert line["assessment_id"] == "assessment-42"


class TestScopedContext:
    def test_context_manager_binds_then_restores(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        log = get_logger("kingsec.test")

        with logging_context(assessment_id="a-1") as cid:
            log.info("inside")

        log.info("outside")

        inside, outside = read_json()
        assert inside["assessment_id"] == "a-1"
        assert inside["correlation_id"] == cid
        # After the block, context is restored to defaults.
        assert outside["assessment_id"] == "-"
        assert outside["correlation_id"] == "-"
