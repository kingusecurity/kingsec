"""Use case: list assessments with pagination.

Powers the Home screen. Returns a lightweight summary of each assessment
(excludes findings to keep payload small). Ordered by created_at DESC
(most recent first).

The total count for pagination metadata comes from the repository's list
method. A future optimization could add a ``count()`` method to the repository
port if the database grows large enough to warrant it.
"""

from __future__ import annotations

from ..dto import (
    AssessmentSummary,
    ListAssessmentsRequest,
    ListAssessmentsResponse,
)
from ..ports import AssessmentRepository


class ListAssessments:
    """List assessments with pagination."""

    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: ListAssessmentsRequest) -> ListAssessmentsResponse:
        # Clamp limits to sane bounds.
        limit = min(max(request.limit, 1), 200)
        offset = max(request.offset, 0)

        assessments = self._assessments.list(limit=limit, offset=offset)

        items = tuple(AssessmentSummary.from_domain(a) for a in assessments)

        return ListAssessmentsResponse(
            items=items,
            total=len(items),
            limit=limit,
            offset=offset,
        )
