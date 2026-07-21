"""GetAssessment, GenerateReport, and port abstractness."""

from __future__ import annotations

import pytest
from tests.unit.application.conftest import (
    InMemoryAssessmentRepository,
    InMemoryReportRepository,
    StubReportGenerator,
    StubScanner,
    make_findings,
)

from kingsec.application import (
    AssessmentNotFoundError,
    GenerateReport,
    GenerateReportRequest,
    GetAssessment,
    GetAssessmentRequest,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.application.ports import (
    AIPort,
    AssessmentRepository,
    ReportGeneratorPort,
    ReportRepository,
    ScannerPort,
)
from kingsec.domain import (
    Assessment,
    Authorization,
    IllegalStateTransition,
    Severity,
    Target,
    TargetType,
)


def _completed(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessments.save(assessment)
    StartAssessment(assessments, StubScanner(make_findings())).execute(
        StartAssessmentRequest(str(assessment.id))
    )
    return assessment


class TestGetAssessment:
    def test_returns_mapped_view(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _completed(assessments)
        view = GetAssessment(assessments).execute(GetAssessmentRequest(str(assessment.id)))

        assert view.assessment_id == str(assessment.id)
        assert view.status == "completed"
        assert view.is_authorized is True
        assert len(view.findings) == 2
        # Findings are ordered as recorded; both are represented as views.
        titles = {f.title for f in view.findings}
        assert "SQL Injection" in titles

    def test_unknown_raises_not_found(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        with pytest.raises(AssessmentNotFoundError):
            GetAssessment(assessments).execute(GetAssessmentRequest("asmt-missing"))


class TestGenerateReport:
    def test_generates_persists_and_renders(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        assessment = _completed(assessments)
        response = GenerateReport(assessments, reports, generator).execute(
            GenerateReportRequest(str(assessment.id))
        )

        # Conclusions-first summary.
        assert response.highest_severity == Severity.CRITICAL.label
        assert response.action_required is True
        assert response.total_findings == 2
        # Deliverable metadata came from the generator port.
        assert response.artifact_media_type == "application/pdf"
        assert response.artifact_bytes > 0
        # The snapshot was persisted for later retrieval.
        assert reports.get(assessment.id).total_findings == 2

    def test_report_for_incomplete_assessment_raises(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # Authorized but never run -> not COMPLETED -> domain refuses a report.
        assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
        assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
        assessments.save(assessment)

        with pytest.raises(IllegalStateTransition):
            GenerateReport(assessments, reports, generator).execute(
                GenerateReportRequest(str(assessment.id))
            )


class TestPortsAreAbstract:
    @pytest.mark.parametrize(
        "port",
        [
            AssessmentRepository,
            ReportRepository,
            ScannerPort,
            AIPort,
            ReportGeneratorPort,
        ],
    )
    def test_cannot_instantiate_abstract_port(self, port: type) -> None:
        # @abstractmethod means an incomplete/abstract port cannot be created.
        with pytest.raises(TypeError):
            port()  # type: ignore[abstract]

    def test_incomplete_implementation_cannot_instantiate(self) -> None:
        class HalfBaked(AssessmentRepository):
            def save(self, assessment) -> None:  # missing get()
                ...

        with pytest.raises(TypeError):
            HalfBaked()  # type: ignore[abstract]
