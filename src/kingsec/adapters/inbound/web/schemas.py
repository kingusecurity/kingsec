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

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kingsec.domain.target import Target, TargetType

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

    @model_validator(mode="after")
    def _validate_target(self) -> CreateAssessmentBody:
        try:
            ttype = TargetType(self.target_type)
        except ValueError as exc:
            raise ValueError(f"invalid target type: {self.target_type}") from exc
        try:
            Target(value=self.target_value, type=ttype)
        except Exception as exc:
            raise ValueError(str(exc)) from exc
        return self

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
    profile_id: str | None = Field(
        default=None,
        description="Assessment profile to plan this scan against. Omit to run every target-compatible scanner (the pre-profile default behavior).",
        examples=["quick-scan"],
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


class ScannerSummaryResponse(BaseModel):
    """Nested per-scanner outcome inside an assessment view."""

    model_config = ConfigDict(extra="forbid")

    scanner_id: str
    name: str
    status: str
    findings_count: int
    skipped_reason: str | None = None


class AssessmentResponse(BaseModel):
    """GET /api/v1/assessments/{id} response body."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str
    findings: list[FindingResponse]
    profile_id: str | None = None
    scanner_summary: list[ScannerSummaryResponse] = Field(default_factory=list)


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
    """POST /api/v1/auth/login response body.

    Two shapes: fully authenticated (access_token/refresh_token populated,
    mfa_required false) or MFA still required (mfa_required true,
    pending_token populated, access_token/refresh_token absent). See
    application.dto.LoginResponse for the full explanation.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    role: str
    access_token: str | None = None
    refresh_token: str | None = None
    mfa_required: bool = False
    pending_token: str | None = None
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


class RegisterUserResponse(BaseModel):
    """POST /api/v1/auth/register response body."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    email: str
    role: str


class AssignRoleBody(BaseModel):
    """PUT /api/v1/users/{user_id}/role request body."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(
        ...,
        min_length=1,
        description="Target role: viewer, analyst, or admin.",
    )


class AssignRoleResponse(BaseModel):
    """PUT /api/v1/users/{user_id}/role response body."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    email: str
    new_role: str


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


class UserListEntryResponse(BaseModel):
    """Single user entry in a user list response."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None = None


class ListUsersResponse(BaseModel):
    """GET /api/v1/users response body."""

    model_config = ConfigDict(extra="forbid")

    items: list[UserListEntryResponse]
    total: int
    limit: int
    offset: int


class FindingListEntryResponse(BaseModel):
    """Single finding entry in findings list."""

    model_config = ConfigDict(extra="forbid")

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


class ListFindingsResponse(BaseModel):
    """GET /api/v1/findings response body."""

    model_config = ConfigDict(extra="forbid")

    items: list[FindingListEntryResponse]
    total: int
    limit: int
    offset: int


class ReportListEntryResponse(BaseModel):
    """Single report entry in reports list."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    target: str
    generated_at: str
    verdict_headline: str
    verdict_highest_severity: str | None = None
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


class ReportDetailResponse(ReportListEntryResponse):
    """Extended report metadata for detail view."""


class ListReportsResponse(BaseModel):
    """GET /api/v1/reports response body."""

    model_config = ConfigDict(extra="forbid")

    items: list[ReportListEntryResponse]
    total: int
    limit: int
    offset: int


class AdminUserActionResponse(BaseModel):
    """Response from user deactivation/activation/reset."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    email: str
    role: str
    is_active: bool


class AdminResetPasswordBody(BaseModel):
    """POST /api/v1/users/{id}/reset-password request body."""

    model_config = ConfigDict(extra="forbid")

    new_password: str


class ChangePasswordBody(BaseModel):
    """POST /api/v1/auth/change-password request body."""

    model_config = ConfigDict(extra="forbid")

    current_password: str
    new_password: str


class RolePermissionResponse(BaseModel):
    """A single role with its permissions."""

    model_config = ConfigDict(extra="forbid")

    role: str
    description: str
    permissions: list[str]


class ListRolesResponse(BaseModel):
    """GET /api/v1/roles response body."""

    model_config = ConfigDict(extra="forbid")

    roles: list[RolePermissionResponse]


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
    limit: int
    offset: int


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
