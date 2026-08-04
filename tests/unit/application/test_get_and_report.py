"""GetAssessment, GenerateReport, and port abstractness."""

from __future__ import annotations

import pytest
from tests.unit.application.conftest import (
    FailingAI,
    InMemoryAssessmentRepository,
    InMemoryReportRepository,
    StubAI,
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
    StartAssessment(assessments, StubScanner(make_findings())).execute(StartAssessmentRequest(str(assessment.id)))
    return assessment


class TestGetAssessment:
    def test_returns_mapped_view(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _completed(assessments)
        view = GetAssessment(assessments).execute(GetAssessmentRequest(str(assessment.id), is_admin=True))

        assert view.assessment_id == str(assessment.id)
        assert view.status == "completed"
        assert view.is_authorized is True
        assert len(view.findings) == 2
        # Findings are ordered as recorded; both are represented as views.
        titles = {f.title for f in view.findings}
        assert "SQL Injection" in titles

    def test_unknown_raises_not_found(self, assessments: InMemoryAssessmentRepository) -> None:
        with pytest.raises(AssessmentNotFoundError):
            GetAssessment(assessments).execute(GetAssessmentRequest("asmt-missing", is_admin=True))


class TestGenerateReport:
    def test_generates_persists_and_renders(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        assessment = _completed(assessments)
        response = GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(assessment.id), is_admin=True))

        # Conclusions-first summary.
        assert response.highest_severity == Severity.CRITICAL.label
        assert response.action_required is True
        assert response.total_findings == 2
        # Deliverable metadata came from the generator port.
        assert response.artifact_media_type == "application/pdf"
        assert response.artifact_bytes > 0
        # The snapshot was persisted for later retrieval.
        assert reports.get(assessment.id).total_findings == 2

    def test_no_ai_port_leaves_report_unenriched(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        assessment = _completed(assessments)
        GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(assessment.id), is_admin=True))

        report = reports.get(assessment.id)
        assert report.ai_enabled is False
        assert all(entry.ai_explanation is None for entry in report.entries)

    def test_ai_port_enriches_every_entry(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        assessment = _completed(assessments)
        GenerateReport(assessments, reports, generator, ai=StubAI()).execute(
            GenerateReportRequest(str(assessment.id), is_admin=True)
        )

        report = reports.get(assessment.id)
        assert report.ai_enabled is True
        assert all(entry.ai_explanation is not None for entry in report.entries)

    def test_failing_ai_degrades_gracefully(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # A failing AI provider must never break report generation — same
        # best-effort contract as scan-time enrichment in submit_assessment.py.
        assessment = _completed(assessments)
        response = GenerateReport(assessments, reports, generator, ai=FailingAI()).execute(
            GenerateReportRequest(str(assessment.id), is_admin=True)
        )
        assert response.total_findings == 2

        report = reports.get(assessment.id)
        assert report.ai_enabled is True  # a provider WAS configured...
        assert all(entry.ai_explanation is None for entry in report.entries)  # ...but every call failed

    def test_first_report_for_a_target_has_no_history(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        assessment = _completed(assessments)
        GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(assessment.id), is_admin=True))

        assert reports.get(assessment.id).history == ()

    def test_second_report_for_same_target_sees_prior_score(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # _completed() always targets "10.0.0.5" — two calls give two
        # different assessments against the same target, exactly the
        # same-target-different-assessment shape history is meant to chart.
        # Also the positive-case counterpart to the self-exclusion regression
        # test below: proves _with_history()'s `assessment_id != report.
        # assessment_id` filter excludes ONLY the report's own assessment,
        # not a genuinely different one for the same target.
        first = _completed(assessments)
        GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(first.id), is_admin=True))
        first_score = reports.get(first.id).executive_score

        second = _completed(assessments)
        GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(second.id), is_admin=True))

        history = reports.get(second.id).history
        assert len(history) == 1
        assert history[0].executive_score == first_score

    def test_regenerating_the_same_report_does_not_duplicate_itself_in_history(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # Regression test: regenerating a report for the SAME assessment
        # previously pulled that assessment's own prior save back in as if
        # it were a separate historical data point, since the history query
        # ran before this assessment's own row existed the first time but
        # found it (and mistook it for someone else's report) on every
        # generation after that.
        assessment = _completed(assessments)
        uc = GenerateReport(assessments, reports, generator)

        uc.execute(GenerateReportRequest(str(assessment.id), is_admin=True))
        assert reports.get(assessment.id).history == ()  # nothing else exists yet

        uc.execute(GenerateReportRequest(str(assessment.id), is_admin=True))
        uc.execute(GenerateReportRequest(str(assessment.id), is_admin=True))

        # No matter how many times the SAME assessment's report is
        # regenerated, it must never appear in its own history.
        assert reports.get(assessment.id).history == ()

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
            GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(assessment.id), is_admin=True))


class TestGetAssessmentAccessControl:
    def test_non_owner_gets_not_found(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _completed(assessments)
        assessment.set_ownership("alice")
        assessments.save(assessment)

        with pytest.raises(AssessmentNotFoundError):
            GetAssessment(assessments).execute(
                GetAssessmentRequest(str(assessment.id), requesting_user="bob", is_admin=False)
            )

    def test_owner_can_get(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _completed(assessments)
        assessment.set_ownership("alice")
        assessments.save(assessment)

        view = GetAssessment(assessments).execute(
            GetAssessmentRequest(str(assessment.id), requesting_user="alice", is_admin=False)
        )

        assert view.assessment_id == str(assessment.id)


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
