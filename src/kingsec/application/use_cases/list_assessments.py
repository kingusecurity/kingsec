"""Use case: list assessments with pagination.

Powers the Home screen. Returns a lightweight summary of each assessment
(excludes findings to keep payload small). Ordered by created_at DESC
(most recent first).

The total count for pagination metadata comes from the repository's list
method. A future optimization could add a ``count()`` method to the repository
port if the database grows large enough to warrant it.
"""

from __future__ import annotations

from kingsec.application.dto import (
    AssessmentSummary,
    ListAssessmentsRequest,
    ListAssessmentsResponse,
)
from kingsec.application.ports import AssessmentRepository


class ListAssessments:
    """List assessments with pagination."""

    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: ListAssessmentsRequest) -> ListAssessmentsResponse:
        # Clamp limits to sane bounds.
        limit = min(max(request.limit, 1), 200)
        offset = max(request.offset, 0)

        page = self._assessments.list(limit=limit, offset=offset)
        assessments = page.items
        if not request.is_admin:
            assessments = tuple(
                a for a in assessments if a.owner_id and a.owner_id == request.requesting_user
            )

        items = tuple(AssessmentSummary.from_domain(a) for a in assessments)

        return ListAssessmentsResponse(
            items=items,
            total=len(items),
            limit=limit,
            offset=offset,
            # Phase 2B Task 2 Condition 1: a row that exists but couldn't be
            # reconstructed must be visible, not only logged - "9 of 10
            # assessments shown" is a real fact the UI can render. Admin-only:
            # a corrupted row has no domain Assessment to check ownership
            # against, so a non-admin caller cannot be shown even that it
            # exists without risking exposing another tenant's assessment id.
            unreadable_ids=page.unreadable_ids if request.is_admin else (),
        )
