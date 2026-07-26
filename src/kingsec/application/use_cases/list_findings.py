from __future__ import annotations

from dataclasses import dataclass

from kingsec.application.ports import AssessmentRepository


@dataclass(frozen=True)
class ListFindingsRequest:
    limit: int = 50
    offset: int = 0
    severity: str | None = None
    status: str | None = None
    assessment_id: str | None = None
    search: str | None = None
    order_by: str = "discovered_at"
    order_dir: str = "desc"


@dataclass(frozen=True)
class FindingListItem:
    finding_id: str
    assessment_id: str
    target: str
    title: str
    description: str
    severity: str
    status: str
    discovered_at: str
    evidence_count: int
    recommendation_count: int


@dataclass(frozen=True)
class ListFindingsResponse:
    items: tuple[FindingListItem, ...]
    total: int
    limit: int
    offset: int


class ListFindings:
    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: ListFindingsRequest) -> ListFindingsResponse:
        projections, total = self._assessments.search_findings(
            severity=request.severity,
            status=request.status,
            assessment_id=request.assessment_id,
            search=request.search,
            order_by=request.order_by,
            order_dir=request.order_dir,
            limit=request.limit,
            offset=request.offset,
        )
        items = tuple(
            FindingListItem(
                finding_id=p.finding_id,
                assessment_id=p.assessment_id,
                target=p.target,
                title=p.title,
                description=p.description,
                severity=p.severity,
                status=p.status,
                discovered_at=p.discovered_at,
                evidence_count=p.evidence_count,
                recommendation_count=p.recommendation_count,
            )
            for p in projections
        )
        return ListFindingsResponse(
            items=items,
            total=total,
            limit=request.limit,
            offset=request.offset,
        )
