"""Test doubles and fixtures for application-layer tests.

The fakes below SUBCLASS the abstract ports — which is exactly how a real
infrastructure adapter will. That the fakes are trivial to write is evidence the
ports are well-shaped. Using real (fake) implementations rather than mocks keeps
the tests behavioural: we assert on outcomes, not on which methods were called.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

# RenderedReport is an APPLICATION DTO (output of ReportGeneratorPort), not domain.
from kingsec.application import (
    AssessmentNotFoundError,
    RenderedReport,
    ReportNotFoundError,
)
from kingsec.application.ports import (
    AIPort,
    AssessmentRepository,
    ReportGeneratorPort,
    ReportRepository,
    ScannerPort,
)
from kingsec.application.ports.repositories import FindingProjection, ReportProjection
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Finding,
    Recommendation,
    Report,
    Severity,
    Target,
)

# --- fake repositories -------------------------------------------------------


class InMemoryAssessmentRepository(AssessmentRepository):
    def __init__(self) -> None:
        self._store: dict[str, Assessment] = {}

    def save(self, assessment: Assessment) -> None:
        self._store[assessment.id.value] = assessment

    def get(self, assessment_id: AssessmentId) -> Assessment:
        try:
            return self._store[assessment_id.value]
        except KeyError:
            raise AssessmentNotFoundError(assessment_id.value) from None

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Assessment]:
        ordered = sorted(self._store.values(), key=lambda a: a.created_at, reverse=True)
        return ordered[offset : offset + limit]

    def delete(self, assessment_id: AssessmentId) -> None:
        if assessment_id.value not in self._store:
            raise AssessmentNotFoundError(assessment_id.value)
        del self._store[assessment_id.value]

    def search_findings(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        order_by: str = "discovered_at",
        order_dir: str = "desc",
        limit: int = 50,
        offset: int = 0,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[list[FindingProjection], int]:
        return [], 0


class InMemoryReportRepository(ReportRepository):
    def __init__(self) -> None:
        self._store: dict[str, Report] = {}

    def save(self, report: Report) -> None:
        self._store[report.assessment_id] = report

    def get(self, assessment_id: AssessmentId) -> Report:
        try:
            return self._store[assessment_id.value]
        except KeyError:
            raise ReportNotFoundError(assessment_id.value) from None

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "generated_at",
        order_dir: str = "desc",
        search: str | None = None,
        severity: str | None = None,
        target: str | None = None,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[list[ReportProjection], int]:
        # Ownership filtering isn't modeled here (Report has no owner field;
        # the real adapter joins through Assessment) — these tests exercise
        # GenerateReport's own logic, not the ownership boundary, which has
        # its own integration test coverage against the real repository.
        reports = list(self._store.values())
        if target is not None:
            reports = [r for r in reports if r.target == target]
        reports.sort(key=lambda r: r.generated_at, reverse=(order_dir == "desc"))
        total = len(reports)
        page = reports[offset : offset + limit]
        projections = [
            ReportProjection(
                assessment_id=r.assessment_id,
                target=r.target,
                generated_at=r.generated_at.isoformat(),
                verdict_headline=r.verdict.headline,
                verdict_highest_severity=(r.verdict.highest_severity.name if r.verdict.highest_severity else None),
                verdict_action_required=r.verdict.action_required,
                total_findings=r.total_findings,
                executive_score=r.executive_score,
            )
            for r in page
        ]
        return projections, total

    def count(self) -> int:
        return 0


# --- fake services -----------------------------------------------------------


class StubScanner(ScannerPort):
    """Returns a fixed set of findings regardless of target."""

    def __init__(self, findings: Sequence[Finding]) -> None:
        self._findings = list(findings)

    def scan(self, target: Target) -> Sequence[Finding]:
        return list(self._findings)


class StubAI(AIPort):
    def recommend(self, finding: Finding) -> Recommendation:
        return Recommendation(
            title=f"Fix {finding.title}",
            description="AI-generated remediation guidance.",
            priority=finding.severity,
        )

    def explain_business_risk(self, finding: Finding) -> str:
        return f"AI-generated business-risk explanation for {finding.title}."


class FailingAI(AIPort):
    def recommend(self, finding: Finding) -> Recommendation:
        raise RuntimeError("AI provider unavailable")

    def explain_business_risk(self, finding: Finding) -> str:
        raise RuntimeError("AI provider unavailable")


class StubReportGenerator(ReportGeneratorPort):
    def render(self, report: Report) -> RenderedReport:
        return RenderedReport(
            content=b"%PDF-1.7 fake report bytes",
            media_type="application/pdf",
            filename=f"{report.assessment_id}.pdf",
        )


# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def assessments() -> InMemoryAssessmentRepository:
    return InMemoryAssessmentRepository()


@pytest.fixture
def reports() -> InMemoryReportRepository:
    return InMemoryReportRepository()


@pytest.fixture
def generator() -> StubReportGenerator:
    return StubReportGenerator()


def make_findings() -> list[Finding]:
    return [
        Finding.create("SQL Injection", "id param injectable", Severity.CRITICAL),
        Finding.create("Missing security headers", "no CSP", Severity.LOW),
    ]
