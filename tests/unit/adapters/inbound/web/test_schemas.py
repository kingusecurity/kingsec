"""Tests for HTTP boundary schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kingsec.adapters.inbound.web.schemas import (
    AssessmentResponse,
    CreateAssessmentBody,
    ErrorResponse,
    FindingResponse,
    GenerateReportResponse,
    HealthResponse,
    SeverityCountResponse,
    StartAssessmentResponse,
)


class TestCreateAssessmentBody:
    def test_valid_minimal(self) -> None:
        body = CreateAssessmentBody(
            target_value="10.0.0.5",
            target_type="ip_address",
            authorized_by="admin@co.com",
            scope="10.0.0.5",
        )
        assert body.target_value == "10.0.0.5"
        assert body.target_type == "ip_address"

    def test_empty_target_value_rejected(self) -> None:
        with pytest.raises(ValidationError, match="min_length"):
            CreateAssessmentBody(
                target_value="",
                target_type="ip_address",
                authorized_by="admin",
                scope="10.0.0.5",
            )

    def test_empty_target_type_rejected(self) -> None:
        with pytest.raises(ValidationError, match="min_length"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
                target_type="",
                authorized_by="admin",
                scope="10.0.0.5",
            )

    def test_empty_authorized_by_rejected(self) -> None:
        with pytest.raises(ValidationError, match="min_length"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
                target_type="ip_address",
                authorized_by="",
                scope="10.0.0.5",
            )

    def test_empty_scope_rejected(self) -> None:
        with pytest.raises(ValidationError, match="min_length"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
                target_type="ip_address",
                authorized_by="admin",
                scope="",
            )

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
                target_type="ip_address",
                authorized_by="admin",
                scope="10.0.0.5",
                sneaky_field="should fail",
            )

    def test_missing_required_field(self) -> None:
        with pytest.raises(ValidationError, match="field required"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
            )


class TestFindingResponse:
    def test_valid(self) -> None:
        finding = FindingResponse(
            finding_id="find-001",
            title="SQL Injection",
            severity="critical",
            status="open",
            evidence_count=2,
            recommendation_count=1,
        )
        assert finding.finding_id == "find-001"
        assert finding.severity == "critical"


class TestAssessmentResponse:
    def test_valid_with_findings(self) -> None:
        finding = FindingResponse(
            finding_id="find-001",
            title="SQLi",
            severity="critical",
            status="open",
            evidence_count=1,
            recommendation_count=1,
        )
        response = AssessmentResponse(
            assessment_id="asmt-001",
            target="10.0.0.5 (ip_address)",
            status="completed",
            is_authorized=True,
            created_at="2026-01-01T00:00:00+00:00",
            findings=[finding],
        )
        assert len(response.findings) == 1
        assert response.findings[0].title == "SQLi"


class TestErrorResponse:
    def test_valid(self) -> None:
        err = ErrorResponse(error_code="KS-VAL-001", message="Invalid input.")
        assert err.error_code == "KS-VAL-001"


class TestHealthResponse:
    def test_default_status(self) -> None:
        h = HealthResponse()
        assert h.status == "ok"


class TestStartAssessmentResponse:
    def test_valid(self) -> None:
        resp = StartAssessmentResponse(
            assessment_id="asmt-001",
            status="completed",
            findings_count=3,
            highest_severity="high",
        )
        assert resp.findings_count == 3

    def test_highest_severity_optional(self) -> None:
        resp = StartAssessmentResponse(
            assessment_id="asmt-001",
            status="completed",
            findings_count=0,
        )
        assert resp.highest_severity is None


class TestSeverityCountResponse:
    def test_valid(self) -> None:
        sc = SeverityCountResponse(severity="critical", count=2)
        assert sc.count == 2


class TestGenerateReportResponse:
    def test_valid(self) -> None:
        resp = GenerateReportResponse(
            assessment_id="asmt-001",
            verdict="Needs attention",
            action_required=True,
            highest_severity="critical",
            total_findings=5,
            severity_counts=[SeverityCountResponse(severity="critical", count=2)],
            artifact_media_type="application/pdf",
            artifact_filename="report.pdf",
            artifact_bytes=1024,
        )
        assert resp.total_findings == 5
        assert len(resp.severity_counts) == 1
