"""ListAssessments use case: pagination, empty state, ordering."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.unit.application.conftest import InMemoryAssessmentRepository

from kingsec.application import (
    AssessmentSummary,
    ListAssessments,
    ListAssessmentsRequest,
    ListAssessmentsResponse,
)
from kingsec.domain import (
    Assessment,
    AssessmentStatus,
    Authorization,
    Target,
    TargetType,
)


def _make_assessment(
    *,
    target_value: str = "10.0.0.5",
    day: int = 1,
) -> Assessment:
    assessment = Assessment.create(
        Target(target_value, TargetType.IP_ADDRESS),
        created_at=datetime(2026, 1, day, tzinfo=UTC),
    )
    assessment.authorize(Authorization.grant("tester", scope=target_value))
    return assessment


class TestHappyPath:
    def test_returns_empty_list_when_no_assessments(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest())

        assert isinstance(response, ListAssessmentsResponse)
        assert response.items == ()
        assert response.total == 0

    def test_returns_assessments_ordered_by_created_at_desc(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        old = _make_assessment(target_value="10.0.0.1", day=1)
        assessments.save(old)
        new = _make_assessment(target_value="10.0.0.2", day=5)
        assessments.save(new)
        mid = _make_assessment(target_value="10.0.0.3", day=3)
        assessments.save(mid)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest())

        assert len(response.items) == 3
        assert response.items[0].target == "10.0.0.2 (ip_address)"
        assert response.items[1].target == "10.0.0.3 (ip_address)"
        assert response.items[2].target == "10.0.0.1 (ip_address)"

    def test_assessment_summary_fields(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _make_assessment(target_value="192.168.1.1", day=1)
        assessments.save(assessment)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest())

        assert len(response.items) == 1
        summary = response.items[0]
        assert summary.assessment_id == str(assessment.id)
        assert summary.target == "192.168.1.1 (ip_address)"
        assert summary.status == AssessmentStatus.AUTHORIZED.value
        assert summary.is_authorized is True
        assert summary.findings_count == 0


class TestPagination:
    def test_limit_controls_page_size(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        for i in range(5):
            assessments.save(_make_assessment(target_value=f"10.0.0.{i}", day=i + 1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=2, offset=0))

        assert len(response.items) == 2
        assert response.limit == 2
        assert response.offset == 0

    def test_offset_skips_results(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        for i in range(5):
            assessments.save(_make_assessment(target_value=f"10.0.0.{i}", day=i + 1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=2, offset=2))

        assert len(response.items) == 2

    def test_limit_clamped_to_max_200(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=999))

        assert response.limit == 200

    def test_limit_clamped_to_min_1(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=0))

        assert response.limit == 1

    def test_offset_negative_becomes_zero(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessments.save(_make_assessment(target_value="10.0.0.1", day=1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(offset=-5))

        assert response.offset == 0
        assert len(response.items) == 1

    def test_offset_beyond_total_returns_empty(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessments.save(_make_assessment(target_value="10.0.0.1", day=1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(offset=100))

        assert response.items == ()
        assert response.total == 0


class TestAssessmentSummary:
    def test_from_domain_mapping(self) -> None:
        assessment = Assessment.create(
            Target("10.0.0.5", TargetType.IP_ADDRESS),
            created_at=datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
        )

        summary = AssessmentSummary.from_domain(assessment)

        assert summary.assessment_id == str(assessment.id)
        assert summary.target == "10.0.0.5 (ip_address)"
        assert summary.status == "draft"
        assert summary.is_authorized is False
        assert summary.findings_count == 0
        assert "2026-06-15" in summary.created_at
