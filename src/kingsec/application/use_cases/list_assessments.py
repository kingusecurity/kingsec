"""Use case: list assessments with filtering, sorting, and pagination.

Powers the Home screen. Returns a lightweight summary of each assessment
(excludes findings to keep payload small). Ordered by created_at DESC
(most recent first).

The repository applies ownership and filters before pagination and returns the
matching total alongside the page. This keeps non-admin pagination both secure
and complete (a page cannot be consumed by another user's rows).
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

        page = self._assessments.list(
            limit=limit,
            offset=offset,
            search=request.search,
            status=request.status,
            order_by=request.order_by,
            order_dir=request.order_dir,
            requesting_user=request.requesting_user,
            is_admin=request.is_admin,
        )
        items = tuple(AssessmentSummary.from_domain(a) for a in page.items)

        return ListAssessmentsResponse(
            items=items,
            total=page.total,
            limit=limit,
            offset=offset,
            # Phase 2B Task 2 Condition 1: a row that exists but couldn't be
            # reconstructed must be visible, not only logged - "9 of 10
            # assessments shown" is a real fact the UI can render. The
            # repository scopes ownership before reconstruction, so these ids
            # are safe and relevant for non-admin callers too.
            unreadable_ids=page.unreadable_ids,
        )
