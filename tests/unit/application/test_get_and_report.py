"""GetAssessment, GenerateReport, and port abstractness."""

from __future__ import annotations

import dataclasses

import pytest
from tests.unit.application.conftest import (
    CountingAI,
    FailingAI,
    InMemoryAssessmentRepository,
    InMemoryReportRepository,
    StubAI,
    StubReportGenerator,
    UnconfiguredAI,
    make_findings,
)

from kingsec.application import (
    AssessmentNotFoundError,
    GenerateReport,
    GenerateReportRequest,
    GetAssessment,
    GetAssessmentRequest,
)
from kingsec.application.ports import (
    AIPort,
    AssessmentRepository,
    ReportGeneratorPort,
    ReportRepository,
    ScannerPort,
)
from kingsec.application.use_cases.generate_report import _AI_ENRICHMENT_MAX_CALLS
from kingsec.domain import (
    Assessment,
    Authorization,
    Finding,
    IllegalStateTransition,
    Severity,
    Target,
    TargetType,
)


def _completed(assessments: InMemoryAssessmentRepository, findings: list[Finding] | None = None) -> Assessment:
    """A COMPLETED assessment with recorded findings - pure setup for tests
    that exercise GetAssessment/GenerateReport, not scan orchestration
    itself (that has its own coverage in test_submit_assessment.py), so
    this manipulates the domain object directly rather than going through
    a use case."""
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    for finding in findings if findings is not None else make_findings():
        assessment.record_finding(finding)
    assessment.complete()
    assessments.save(assessment)
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

    def test_ai_port_enriches_critical_and_high_entries_only(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # Phase 2B-c Priority 2 (5b): make_findings() is one CRITICAL + one
        # LOW — only the CRITICAL entry qualifies for enrichment under the
        # severity floor.
        assessment = _completed(assessments)
        GenerateReport(assessments, reports, generator, ai=StubAI()).execute(
            GenerateReportRequest(str(assessment.id), is_admin=True)
        )

        report = reports.get(assessment.id)
        assert report.ai_enabled is True
        by_severity = {entry.severity: entry for entry in report.entries}
        assert by_severity[Severity.CRITICAL].ai_explanation is not None
        assert by_severity[Severity.LOW].ai_explanation is None

    def test_unconfigured_ai_skips_entire_pass_without_per_finding_calls(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # Phase 2B-c Priority 2 (5a): UnconfiguredAI raises AssertionError if
        # recommend()/explain_business_risk() is ever called - reaching the
        # assertions below at all proves the whole pass was skipped, not
        # attempted-and-caught per finding (the prior behavior that produced
        # 14,043 identical log lines for one unconfigured report).
        assessment = _completed(assessments)
        GenerateReport(assessments, reports, generator, ai=UnconfiguredAI()).execute(
            GenerateReportRequest(str(assessment.id), is_admin=True)
        )

        report = reports.get(assessment.id)
        assert report.ai_enabled is False
        assert all(entry.ai_explanation is None for entry in report.entries)

    def test_ai_enrichment_has_a_hard_ceiling_regardless_of_severity(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        # Phase 2B-c Priority 2 (5b): a report with far more CRITICAL findings
        # than the ceiling must still never attempt more than the ceiling's
        # worth of AI calls - "Critical and High only" is not itself a bound
        # if a target has thousands of critical-severity findings.
        many_critical = [
            Finding.create(f"Finding {i}", "detail", Severity.CRITICAL) for i in range(_AI_ENRICHMENT_MAX_CALLS + 25)
        ]
        assessment = _completed(assessments, findings=many_critical)
        counting_ai = CountingAI()
        GenerateReport(assessments, reports, generator, ai=counting_ai).execute(
            GenerateReportRequest(str(assessment.id), is_admin=True)
        )

        assert len(counting_ai.explain_calls) == _AI_ENRICHMENT_MAX_CALLS

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

    def test_history_point_carries_the_prior_reports_own_score_version(
        self,
        assessments: InMemoryAssessmentRepository,
        reports: InMemoryReportRepository,
        generator: StubReportGenerator,
    ) -> None:
        """Phase 2C Step 2, Addition B: a history point is meaningless
        without knowing which formula produced its score - a v1-scored
        prior report must still say so in the second report's history,
        not silently inherit "v2" just because that's now the default."""
        first = _completed(assessments)
        GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(first.id), is_admin=True))
        v1_report = dataclasses.replace(reports.get(first.id), score_version="v1")
        reports.save(v1_report)

        second = _completed(assessments)
        GenerateReport(assessments, reports, generator).execute(GenerateReportRequest(str(second.id), is_admin=True))

        history = reports.get(second.id).history
        assert len(history) == 1
        assert history[0].score_version == "v1"

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
