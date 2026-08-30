"""Tests for HTTP boundary schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kingsec.adapters.inbound.web.schemas import (
    AdminResetPasswordBody,
    AssessmentResponse,
    AssignRoleBody,
    ChangePasswordBody,
    CreateAssessmentBody,
    ErrorResponse,
    FindingResponse,
    GenerateReportResponse,
    HealthResponse,
    RefreshTokenBody,
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
        with pytest.raises(ValidationError, match="string_too_short"):
            CreateAssessmentBody(
                target_value="",
                target_type="ip_address",
                authorized_by="admin",
                scope="10.0.0.5",
            )

    def test_empty_target_type_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_short"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
                target_type="",
                authorized_by="admin",
                scope="10.0.0.5",
            )

    def test_empty_authorized_by_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_short"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
                target_type="ip_address",
                authorized_by="",
                scope="10.0.0.5",
            )

    def test_empty_scope_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_short"):
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
        with pytest.raises(ValidationError, match="Field required"):
            CreateAssessmentBody(
                target_value="10.0.0.5",
            )

    # Phase 68 / KSEC-64-04: profile_id previously had no max_length.
    def _make(self, **overrides) -> CreateAssessmentBody:
        defaults = dict(
            target_value="10.0.0.5",
            target_type="ip_address",
            authorized_by="admin",
            scope="10.0.0.5",
        )
        defaults.update(overrides)
        return CreateAssessmentBody(**defaults)

    def test_profile_id_below_limit_accepted(self) -> None:
        body = self._make(profile_id="x" * 127)
        assert body.profile_id == "x" * 127

    def test_profile_id_exact_limit_accepted(self) -> None:
        body = self._make(profile_id="x" * 128)
        assert body.profile_id == "x" * 128

    def test_profile_id_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            self._make(profile_id="x" * 129)


class TestRefreshTokenBody:
    """Phase 68 / KSEC-64-04: refresh_token previously had no max_length."""

    def test_below_limit_accepted(self) -> None:
        body = RefreshTokenBody(refresh_token="x" * 1023)
        assert len(body.refresh_token) == 1023

    def test_exact_limit_accepted(self) -> None:
        body = RefreshTokenBody(refresh_token="x" * 1024)
        assert len(body.refresh_token) == 1024

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            RefreshTokenBody(refresh_token="x" * 1025)

    def test_valid_token_shaped_value_still_accepted(self) -> None:
        """Existing behavior: a realistic JWT-shaped token still passes."""
        body = RefreshTokenBody(refresh_token="a.b.c")
        assert body.refresh_token == "a.b.c"


class TestAssignRoleBody:
    """Phase 68 / KSEC-64-04: role previously had no max_length."""

    def test_below_limit_accepted(self) -> None:
        body = AssignRoleBody(role="x" * 19)
        assert len(body.role) == 19

    def test_exact_limit_accepted(self) -> None:
        body = AssignRoleBody(role="x" * 20)
        assert len(body.role) == 20

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            AssignRoleBody(role="x" * 21)

    def test_real_role_names_still_accepted(self) -> None:
        for role in ("viewer", "analyst", "admin"):
            assert AssignRoleBody(role=role).role == role


class TestAdminResetPasswordBody:
    """Phase 68 / KSEC-64-04: new_password previously had no Field()
    constraints at all. The chosen bounds (8-128) are deliberately
    identical to the canonical policy ChangePassword._validate_password()
    already enforces (Phase 67 / KSEC-64-03) - not a second, competing
    limit."""

    def test_below_limit_accepted(self) -> None:
        body = AdminResetPasswordBody(new_password="x" * 127)
        assert len(body.new_password) == 127

    def test_exact_limit_accepted(self) -> None:
        body = AdminResetPasswordBody(new_password="x" * 128)
        assert len(body.new_password) == 128

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            AdminResetPasswordBody(new_password="x" * 129)

    def test_below_minimum_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_short"):
            AdminResetPasswordBody(new_password="x" * 7)

    def test_valid_password_still_accepted(self) -> None:
        body = AdminResetPasswordBody(new_password="NewSecurePass1")
        assert body.new_password == "NewSecurePass1"


class TestChangePasswordBody:
    """Phase 68 / KSEC-64-04: current_password/new_password previously
    had no Field() constraints at all."""

    def test_current_password_below_limit_accepted(self) -> None:
        body = ChangePasswordBody(current_password="x" * 127, new_password="NewSecurePass1")
        assert len(body.current_password) == 127

    def test_current_password_exact_limit_accepted(self) -> None:
        body = ChangePasswordBody(current_password="x" * 128, new_password="NewSecurePass1")
        assert len(body.current_password) == 128

    def test_current_password_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            ChangePasswordBody(current_password="x" * 129, new_password="NewSecurePass1")

    def test_current_password_short_value_still_accepted(self) -> None:
        """current_password proves knowledge of a possibly pre-policy
        password - it must not be forced to meet the new min_length."""
        body = ChangePasswordBody(current_password="old", new_password="NewSecurePass1")
        assert body.current_password == "old"

    def test_new_password_below_limit_accepted(self) -> None:
        body = ChangePasswordBody(current_password="old", new_password="x" * 127)
        assert len(body.new_password) == 127

    def test_new_password_exact_limit_accepted(self) -> None:
        body = ChangePasswordBody(current_password="old", new_password="x" * 128)
        assert len(body.new_password) == 128

    def test_new_password_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            ChangePasswordBody(current_password="old", new_password="x" * 129)

    def test_new_password_below_minimum_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_short"):
            ChangePasswordBody(current_password="old", new_password="x" * 7)

    def test_valid_change_still_accepted(self) -> None:
        body = ChangePasswordBody(current_password="oldpassword", new_password="NewSecurePass1")
        assert body.new_password == "NewSecurePass1"


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
            job_id="job-001",
        )
        assert resp.assessment_id == "asmt-001"
        assert resp.status == "completed"
        assert resp.job_id == "job-001"

    def test_job_id_optional(self) -> None:
        resp = StartAssessmentResponse(
            assessment_id="asmt-001",
            status="completed",
        )
        assert resp.job_id is None


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
