"""Unit tests for the shared Signal 2 (baseline-shape clustering) logic."""

from __future__ import annotations

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.severity_demotion import (
    ShapeCandidate,
    compute_baseline_shape_demotions,
)


def _candidates(shapes: list[tuple[int, int]], severity: Severity = Severity.HIGH) -> list[ShapeCandidate]:
    return [
        ShapeCandidate(index=i, status=status, length=length, base_severity=severity)
        for i, (status, length) in enumerate(shapes)
    ]


class TestComputeBaselineShapeDemotions:
    def test_no_candidates_demotes_nothing(self) -> None:
        assert compute_baseline_shape_demotions([], total_results=100) == frozenset()

    def test_zero_total_results_demotes_nothing(self) -> None:
        assert compute_baseline_shape_demotions(_candidates([(200, 100)] * 10), total_results=0) == frozenset()

    def test_below_occurrence_floor_does_not_trigger(self) -> None:
        # 4 occurrences, well above 3% of a tiny batch, but below the >=5 floor.
        candidates = _candidates([(200, 9000)] * 4)
        assert compute_baseline_shape_demotions(candidates, total_results=10) == frozenset()

    def test_below_percentage_floor_does_not_trigger(self) -> None:
        # 5 occurrences (clears the floor) but only 0.5% of a 1,000-result batch.
        candidates = _candidates([(200, 9000)] * 5)
        assert compute_baseline_shape_demotions(candidates, total_results=1000) == frozenset()

    def test_the_4600_result_worked_example_from_the_approved_plan(self) -> None:
        # 900 of 4,600 total results share one shape = 19.6% - the exact case
        # the user's approved plan said the old >=20% threshold would miss.
        candidates = _candidates([(200, 9216)] * 900)
        demoted = compute_baseline_shape_demotions(candidates, total_results=4600)
        assert len(demoted) == 900

    def test_138_of_4600_is_exactly_the_3_percent_worked_example(self) -> None:
        candidates = _candidates([(200, 9216)] * 138)
        demoted = compute_baseline_shape_demotions(candidates, total_results=4600)
        assert len(demoted) == 138

    def test_137_of_4600_falls_just_short_of_3_percent(self) -> None:
        candidates = _candidates([(200, 9216)] * 137)
        assert compute_baseline_shape_demotions(candidates, total_results=4600) == frozenset()

    def test_only_the_dominant_shape_is_demoted_not_minority_shapes(self) -> None:
        candidates = _candidates([(200, 9216)] * 10 + [(200, 1234)] * 2)
        demoted = compute_baseline_shape_demotions(candidates, total_results=100)
        assert len(demoted) == 10
        assert all(candidates[i].length == 9216 for i in demoted)

    def test_ten_identical_shaped_200s_across_distinct_paths_is_near_certain(self) -> None:
        # Directly from the approved plan's own rationale: "Ten identical-
        # shaped 200s across ten different sensitive paths is a catch-all
        # with near-certainty."
        candidates = _candidates([(200, 4096)] * 10)
        demoted = compute_baseline_shape_demotions(candidates, total_results=50)
        assert demoted == frozenset(range(10))

    def test_returns_original_indices_not_positions(self) -> None:
        candidates = [
            ShapeCandidate(index=41, status=200, length=100, base_severity=Severity.HIGH),
            ShapeCandidate(index=99, status=200, length=100, base_severity=Severity.HIGH),
            ShapeCandidate(index=7, status=200, length=100, base_severity=Severity.HIGH),
            ShapeCandidate(index=3, status=200, length=100, base_severity=Severity.HIGH),
            ShapeCandidate(index=1, status=200, length=100, base_severity=Severity.HIGH),
        ]
        demoted = compute_baseline_shape_demotions(candidates, total_results=100)
        assert demoted == frozenset({41, 99, 7, 3, 1})
