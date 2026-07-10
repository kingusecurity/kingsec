"""Pydantic models for the HTTP boundary — request and response schemas.

These mirror the application DTOs but live in the adapter layer. The web adapter
translates between these Pydantic models and the flat application DTOs. Keeping
them separate means the HTTP serialisation format can change (field names,
validation rules, documentation) without touching the application core.

Field naming follows JSON conventions (snake_case). Validation is deliberately
strict: unknown fields are rejected (``model_config extra='forbid'``), and every
required field is enforced at the Pydantic level before a use case is ever called.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ── Request schemas ──────────────────────────────────────────────────────────


class CreateAssessmentBody(BaseModel):
    """POST /api/v1/assessments request body."""

    model_config = ConfigDict(extra="forbid")

    target_value: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The target to assess (IP, hostname, or URL).",
        examples=["10.0.0.5"],
    )
    target_type: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Target type: ip_address, hostname, url, or network.",
        examples=["ip_address"],
    )
    authorized_by: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Who authorized this assessment.",
        examples=["admin@company.com"],
    )
    scope: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Scope of authorization (audit trail).",
        examples=["10.0.0.5"],
    )


class StartAssessmentBody(BaseModel):
    """POST /api/v1/assessments/{id}/start request body (empty)."""

    model_config = ConfigDict(extra="forbid")


class GenerateReportBody(BaseModel):
    """POST /api/v1/assessments/{id}/report request body (empty)."""

    model_config = ConfigDict(extra="forbid")


class CancelAssessmentBody(BaseModel):
    """POST /api/v1/assessments/{id}/cancel request body (empty)."""

    model_config = ConfigDict(extra="forbid")


# ── Response schemas ─────────────────────────────────────────────────────────


class ErrorResponse(BaseModel):
    """Standard error response body."""

    model_config = ConfigDict(extra="forbid")

    error_code: str = Field(
        ...,
        description="Stable machine-readable error code.",
        examples=["KS-VAL-001"],
    )
    message: str = Field(
        ...,
        description="Safe, user-facing error message.",
        examples=["The provided input is invalid."],
    )


class HealthResponse(BaseModel):
    """GET /health response body."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(
        default="ok",
        description="Health status.",
    )


class CreateAssessmentResponse(BaseModel):
    """POST /api/v1/assessments response body."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    status: str
    target: str


class FindingResponse(BaseModel):
    """Nested finding inside an assessment view."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    severity: str
    status: str
    evidence_count: int
    recommendation_count: int


class AssessmentResponse(BaseModel):
    """GET /api/v1/assessments/{id} response body."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str
    findings: list[FindingResponse]


class StartAssessmentResponse(BaseModel):
    """POST /api/v1/assessments/{id}/start response body."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    status: str
    job_id: str | None = None


class SeverityCountResponse(BaseModel):
    """Severity breakdown entry in a report response."""

    model_config = ConfigDict(extra="forbid")

    severity: str
    count: int


class GenerateReportResponse(BaseModel):
    """POST /api/v1/assessments/{id}/report response body."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    verdict: str
    action_required: bool
    highest_severity: str | None = None
    total_findings: int
    severity_counts: list[SeverityCountResponse]
    artifact_media_type: str
    artifact_filename: str
    artifact_bytes: int


class CancelAssessmentResponse(BaseModel):
    """POST /api/v1/assessments/{id}/cancel response body."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    status: str
