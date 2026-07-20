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


class AssessmentSummaryResponse(BaseModel):
    """Lightweight assessment view inside a list response."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str
    findings_count: int


class ListAssessmentsResponse(BaseModel):
    """GET /api/v1/assessments response body."""

    model_config = ConfigDict(extra="forbid")

    items: list[AssessmentSummaryResponse]
    total: int
    limit: int
    offset: int


# ── Auth schemas ─────────────────────────────────────────────────────────────


class LoginBody(BaseModel):
    """POST /api/v1/auth/login request body."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="The login username.",
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="The login password.",
    )


class LoginResponse(BaseModel):
    """POST /api/v1/auth/login response body."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    role: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenBody(BaseModel):
    """POST /api/v1/auth/refresh request body."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(
        ...,
        min_length=1,
        description="The refresh token to exchange.",
    )


class RefreshTokenResponse(BaseModel):
    """POST /api/v1/auth/refresh response body."""

    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterUserBody(BaseModel):
    """POST /api/v1/auth/register request body."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="Desired login username.",
    )
    email: str = Field(
        ...,
        min_length=5,
        max_length=254,
        description="User email address.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (min 8 chars, mixed case + digit).",
    )
    role: str = Field(
        default="viewer",
        description="User role: viewer, analyst, or admin.",
    )


class RegisterUserResponse(BaseModel):
    """POST /api/v1/auth/register response body."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    email: str
    role: str


class UserResponse(BaseModel):
    """GET /api/v1/auth/me response body."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None = None


# ── Audit schemas ────────────────────────────────────────────────────────────


class AuditEntryResponse(BaseModel):
    """Single audit entry in a list response."""

    model_config = ConfigDict(extra="forbid")

    action: str
    resource_type: str
    resource_id: str
    success: bool
    reason: str
    timestamp: str
    user_id: str
    username: str
    role: str
    ip_address: str
    correlation_id: str


class AuditListResponse(BaseModel):
    """GET /api/v1/audit response body."""

    model_config = ConfigDict(extra="forbid")

    items: list[AuditEntryResponse]
    total: int
    limit: int
    offset: int


# ── API Key schemas ───────────────────────────────────────────────────────────


class CreateApiKeyBody(BaseModel):
    """POST /api/v1/apikeys request body."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable name for the API key.",
        examples=["CI/CD Pipeline"],
    )
    scope: str = Field(
        default="read_only",
        pattern=r"^(read_only|full_access)$",
        description="Operational scope: read_only or full_access.",
    )


class CreateApiKeyResponse(BaseModel):
    """POST /api/v1/apikeys response body."""

    model_config = ConfigDict(extra="forbid")

    api_key_id: str
    name: str
    plaintext_key: str
    scope: str
    created_at: str


class ApiKeyResponse(BaseModel):
    """API key view (no sensitive data)."""

    model_config = ConfigDict(extra="forbid")

    api_key_id: str
    user_id: str
    name: str
    scope: str
    status: str
    last_used_at: str | None = None
    created_at: str


class ApiKeyListResponse(BaseModel):
    """GET /api/v1/apikeys response body."""

    model_config = ConfigDict(extra="forbid")

    items: list[ApiKeyResponse]
    total: int


class RotateApiKeyResponse(BaseModel):
    """POST /api/v1/apikeys/{id}/rotate response body."""

    model_config = ConfigDict(extra="forbid")

    api_key_id: str
    name: str
    plaintext_key: str
    scope: str
    created_at: str


class CurrentApiKeyResponse(BaseModel):
    """GET /api/v1/apikeys/me response body."""

    model_config = ConfigDict(extra="forbid")

    api_key_id: str
    user_id: str
    name: str
    scope: str
    status: str
    last_used_at: str | None = None
    created_at: str


# ── MFA schemas ──────────────────────────────────────────────────────────────


class MfaStatusResponse(BaseModel):
    """GET /api/v1/mfa/status response body."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool


class MfaVerifyBody(BaseModel):
    """POST /api/v1/mfa/verify request body."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)
    totp_code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")


class MfaRecoveryBody(BaseModel):
    """POST /api/v1/mfa/recovery request body."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)
    recovery_code: str = Field(..., min_length=1, description="Recovery code")
