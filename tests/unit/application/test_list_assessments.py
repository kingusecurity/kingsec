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
from kingsec.application.ports.repositories import AssessmentPage
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
    def test_returns_empty_list_when_no_assessments(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(is_admin=True))

        assert isinstance(response, ListAssessmentsResponse)
        assert response.items == ()
        assert response.total == 0

    def test_returns_assessments_ordered_by_created_at_desc(self, assessments: InMemoryAssessmentRepository) -> None:
        old = _make_assessment(target_value="10.0.0.1", day=1)
        assessments.save(old)
        new = _make_assessment(target_value="10.0.0.2", day=5)
        assessments.save(new)
        mid = _make_assessment(target_value="10.0.0.3", day=3)
        assessments.save(mid)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(is_admin=True))

        assert len(response.items) == 3
        assert response.items[0].target == "10.0.0.2 (ip_address)"
        assert response.items[1].target == "10.0.0.3 (ip_address)"
        assert response.items[2].target == "10.0.0.1 (ip_address)"

    def test_assessment_summary_fields(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment(target_value="192.168.1.1", day=1)
        assessments.save(assessment)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(is_admin=True))

        assert len(response.items) == 1
        summary = response.items[0]
        assert summary.assessment_id == str(assessment.id)
        assert summary.target == "192.168.1.1 (ip_address)"
        assert summary.status == AssessmentStatus.AUTHORIZED.value
        assert summary.is_authorized is True
        assert summary.findings_count == 0


class TestPagination:
    def test_limit_controls_page_size(self, assessments: InMemoryAssessmentRepository) -> None:
        for i in range(5):
            assessments.save(_make_assessment(target_value=f"10.0.0.{i}", day=i + 1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=2, offset=0, is_admin=True))

        assert len(response.items) == 2
        assert response.limit == 2
        assert response.offset == 0

    def test_offset_skips_results(self, assessments: InMemoryAssessmentRepository) -> None:
        for i in range(5):
            assessments.save(_make_assessment(target_value=f"10.0.0.{i}", day=i + 1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=2, offset=2, is_admin=True))

        assert len(response.items) == 2

    def test_limit_clamped_to_max_200(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=999, is_admin=True))

        assert response.limit == 200

    def test_limit_clamped_to_min_1(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(limit=0, is_admin=True))

        assert response.limit == 1

    def test_offset_negative_becomes_zero(self, assessments: InMemoryAssessmentRepository) -> None:
        assessments.save(_make_assessment(target_value="10.0.0.1", day=1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(offset=-5, is_admin=True))

        assert response.offset == 0
        assert len(response.items) == 1

    def test_offset_beyond_total_returns_empty(self, assessments: InMemoryAssessmentRepository) -> None:
        assessments.save(_make_assessment(target_value="10.0.0.1", day=1))

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(offset=100, is_admin=True))

        assert response.items == ()
        assert response.total == 1

    def test_total_is_filtered_count_before_pagination(self, assessments: InMemoryAssessmentRepository) -> None:
        for i in range(3):
            assessment = _make_assessment(target_value=f"10.0.0.{i + 1}", day=i + 1)
            assessment.set_ownership("alice")
            assessments.save(assessment)

        use_case = ListAssessments(assessments)
        response = use_case.execute(
            ListAssessmentsRequest(limit=1, requesting_user="alice", is_admin=False)
        )

        assert len(response.items) == 1
        assert response.total == 3


class TestOwnershipFiltering:
    def test_non_admin_only_sees_own_assessments(self, assessments: InMemoryAssessmentRepository) -> None:
        mine = _make_assessment(target_value="10.0.0.1", day=1)
        mine.set_ownership("alice")
        assessments.save(mine)
        theirs = _make_assessment(target_value="10.0.0.2", day=2)
        theirs.set_ownership("bob")
        assessments.save(theirs)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(requesting_user="alice", is_admin=False))

        assert len(response.items) == 1
        assert response.items[0].assessment_id == str(mine.id)

    def test_non_admin_does_not_see_unowned_assessments(self, assessments: InMemoryAssessmentRepository) -> None:
        unowned = _make_assessment(target_value="10.0.0.1", day=1)
        assessments.save(unowned)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(requesting_user="alice", is_admin=False))

        assert response.items == ()

    def test_admin_sees_all_assessments_regardless_of_owner(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        mine = _make_assessment(target_value="10.0.0.1", day=1)
        mine.set_ownership("alice")
        assessments.save(mine)
        theirs = _make_assessment(target_value="10.0.0.2", day=2)
        theirs.set_ownership("bob")
        assessments.save(theirs)

        use_case = ListAssessments(assessments)
        response = use_case.execute(ListAssessmentsRequest(requesting_user="alice", is_admin=True))

        assert len(response.items) == 2

    def test_ownership_is_applied_before_offset_and_limit(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        alice_old = _make_assessment(target_value="10.0.0.1", day=1)
        alice_old.set_ownership("alice")
        assessments.save(alice_old)
        alice_new = _make_assessment(target_value="10.0.0.2", day=3)
        alice_new.set_ownership("alice")
        assessments.save(alice_new)
        bob_newest = _make_assessment(target_value="10.0.0.3", day=4)
        bob_newest.set_ownership("bob")
        assessments.save(bob_newest)

        use_case = ListAssessments(assessments)
        response = use_case.execute(
            ListAssessmentsRequest(limit=1, offset=1, requesting_user="alice", is_admin=False)
        )

        assert response.total == 2
        assert tuple(item.assessment_id for item in response.items) == (str(alice_old.id),)


class TestFilteringAndSorting:
    def test_search_and_status_filters_are_combined(self, assessments: InMemoryAssessmentRepository) -> None:
        matching = _make_assessment(target_value="10.0.0.1", day=1)
        assessments.save(matching)
        wrong_target = _make_assessment(target_value="192.168.1.1", day=2)
        assessments.save(wrong_target)
        wrong_status = _make_assessment(target_value="10.0.0.2", day=3)
        wrong_status.start()
        assessments.save(wrong_status)

        response = ListAssessments(assessments).execute(
            ListAssessmentsRequest(search="10.0.0", status="authorized", is_admin=True)
        )

        assert response.total == 1
        assert tuple(item.assessment_id for item in response.items) == (str(matching.id),)

    def test_target_sort_is_forwarded(self, assessments: InMemoryAssessmentRepository) -> None:
        later_alphabetically = _make_assessment(target_value="10.0.0.20", day=1)
        earlier_alphabetically = _make_assessment(target_value="10.0.0.10", day=2)
        assessments.save(later_alphabetically)
        assessments.save(earlier_alphabetically)

        response = ListAssessments(assessments).execute(
            ListAssessmentsRequest(order_by="target", order_dir="asc", is_admin=True)
        )

        assert tuple(item.assessment_id for item in response.items) == (
            str(earlier_alphabetically.id),
            str(later_alphabetically.id),
        )


class _UnreadableAssessmentRepository(InMemoryAssessmentRepository):
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        status: str | None = None,
        order_by: str = "created_at",
        order_dir: str = "desc",
        requesting_user: str = "",
        is_admin: bool = True,
    ) -> AssessmentPage:
        return AssessmentPage(items=(), total=1, unreadable_ids=("asmt-corrupt",))


class TestUnreadableAssessments:
    def test_admin_receives_unreadable_ids(self) -> None:
        response = ListAssessments(_UnreadableAssessmentRepository()).execute(
            ListAssessmentsRequest(is_admin=True)
        )

        assert response.total == 1
        assert response.unreadable_ids == ("asmt-corrupt",)

    def test_non_admin_receives_repository_scoped_unreadable_ids(self) -> None:
        response = ListAssessments(_UnreadableAssessmentRepository()).execute(
            ListAssessmentsRequest(requesting_user="alice", is_admin=False)
        )

        assert response.total == 1
        assert response.unreadable_ids == ("asmt-corrupt",)


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
