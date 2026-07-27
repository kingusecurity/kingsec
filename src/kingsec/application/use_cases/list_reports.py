from __future__ import annotations

from dataclasses import dataclass

from kingsec.application.ports import ReportRepository


@dataclass(frozen=True)
class ListReportsRequest:
    limit: int = 50
    offset: int = 0
    order_by: str = "generated_at"
    order_dir: str = "desc"
    search: str | None = None
    severity: str | None = None
    target: str | None = None


@dataclass(frozen=True)
class ReportListItem:
    assessment_id: str
    target: str
    generated_at: str
    verdict_headline: str
    verdict_highest_severity: str | None
    verdict_action_required: bool
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    executive_score: float = 0.0
    format: str = "pdf"
    file_size: int = 0


@dataclass(frozen=True)
class ListReportsResponse:
    items: tuple[ReportListItem, ...]
    total: int
    limit: int
    offset: int


class ListReports:
    def __init__(self, reports: ReportRepository) -> None:
        self._reports = reports

    def execute(self, request: ListReportsRequest) -> ListReportsResponse:
        projections, total = self._reports.list(
            limit=request.limit,
            offset=request.offset,
            order_by=request.order_by,
            order_dir=request.order_dir,
            search=request.search,
            severity=request.severity,
            target=request.target,
        )
        items = tuple(
            ReportListItem(
                assessment_id=p.assessment_id,
                target=p.target,
                generated_at=p.generated_at,
                verdict_headline=p.verdict_headline,
                verdict_highest_severity=p.verdict_highest_severity,
                verdict_action_required=p.verdict_action_required,
                total_findings=p.total_findings,
                critical_count=p.critical_count,
                high_count=p.high_count,
                medium_count=p.medium_count,
                low_count=p.low_count,
                info_count=p.info_count,
                executive_score=p.executive_score,
                format=p.format,
                file_size=p.file_size,
            )
            for p in projections
        )
        return ListReportsResponse(
            items=items,
            total=total,
            limit=request.limit,
            offset=request.offset,
        )
