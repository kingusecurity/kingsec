"""Application-layer Data Transfer Objects.

Design decisions:
    - Request DTOs are plain dataclasses (not Pydantic) to keep the
      application layer framework-free.
    - Response DTOs include only the information the caller needs.
    - Sensitive data (passwords, tokens) are never stored in DTOs after use.
    - DTOs are frozen (immutable) to prevent accidental mutation after creation.
    - ``from_domain`` classmethods map domain objects to boundary-safe views,
      keeping the domain layer's internal structure hidden from callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.domain.assessment import Assessment
    from kingsec.domain.finding import Finding


# ── API Key DTOs ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CreateApiKeyRequest:
    """Request to create a new API key."""

    user_id: str
    name: str
    scope: str = "read_only"


@dataclass(frozen=True)
class CreateApiKeyResponse:
    """Response from successful API key creation.

    The ``plaintext_key`` is shown **only once** — it cannot be recovered later.
    """

    api_key_id: str
    name: str
    plaintext_key: str
    scope: str
    created_at: str


@dataclass(frozen=True)
class ApiKeyView:
    """Public view of an API key (no sensitive data)."""

    api_key_id: str
    user_id: str
    name: str
    scope: str
    status: str
    last_used_at: str | None
    created_at: str


@dataclass(frozen=True)
class ListApiKeysRequest:
    """Request to list API keys for a user (admin can list all)."""

    user_id: str
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class RevokeApiKeyRequest:
    """Request to revoke (delete) an API key."""

    api_key_id: str
    requesting_user_id: str


@dataclass(frozen=True)
class RotateApiKeyRequest:
    """Request to rotate an API key (generate a new key while replacing the old)."""

    api_key_id: str
    requesting_user_id: str


@dataclass(frozen=True)
class RotateApiKeyResponse:
    """Response from successful API key rotation."""

    api_key_id: str
    name: str
    plaintext_key: str
    scope: str
    created_at: str


@dataclass(frozen=True)
class ValidateApiKeyRequest:
    """Request to validate a full API key token.

    The ``api_key`` is the full token string (e.g. ``ks_<uuid>_<secret>``).
    The ID is extracted from the token and used to look up the stored hash.
    """

    api_key: str


@dataclass(frozen=True)
class ValidateApiKeyResponse:
    """Response from successful API key validation."""

    api_key_id: str
    user_id: str
    scope: str
    status: str


# ── Authentication DTOs ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class LoginRequest:
    """Request to authenticate a user."""

    username: str
    password: str


@dataclass(frozen=True)
class LoginResponse:
    """Response from successful authentication."""

    user_id: str
    username: str
    role: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # 30 minutes in seconds


@dataclass(frozen=True)
class RefreshTokenRequest:
    """Request to refresh an access token."""

    refresh_token: str


@dataclass(frozen=True)
class RefreshTokenResponse:
    """Response from successful token refresh."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # 30 minutes in seconds


@dataclass(frozen=True)
class RegisterUserRequest:
    """Request to register a new user."""

    username: str
    email: str
    password: str
    role: str = "viewer"  # default to least-privileged


@dataclass(frozen=True)
class RegisterUserResponse:
    """Response from successful user registration."""

    user_id: str
    username: str
    email: str
    role: str


@dataclass(frozen=True)
class UserView:
    """User information view (no sensitive data)."""

    user_id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None


@dataclass(frozen=True)
class ChangePasswordRequest:
    """Request to change a user's password."""

    user_id: str
    current_password: str
    new_password: str


@dataclass(frozen=True)
class AdminChangePasswordRequest:
    """Request for admin to change a user's password."""

    user_id: str
    new_password: str


# ── Assessment DTOs ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CreateAssessmentRequest:
    """Request to create a new assessment."""

    target_value: str
    target_type: str
    authorized_by: str
    scope: str


@dataclass(frozen=True)
class CreateAssessmentResponse:
    """Response from successful assessment creation."""

    assessment_id: str
    status: str
    target: str


@dataclass(frozen=True)
class ListAssessmentsRequest:
    """Request to list assessments with pagination."""

    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class SeverityCount:
    """Aggregate count of findings by severity level."""

    severity: str
    count: int


@dataclass(frozen=True)
class AssessmentSummary:
    """Lightweight assessment summary for list views."""

    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str
    findings_count: int

    @classmethod
    def from_domain(cls, assessment: Assessment) -> AssessmentSummary:
        """Map a domain Assessment aggregate to a boundary-safe summary view."""
        return cls(
            assessment_id=str(assessment.id),
            target=str(assessment.target),
            status=assessment.status.value,
            is_authorized=assessment.is_authorized,
            created_at=assessment.created_at.isoformat(),
            findings_count=len(assessment.findings),
        )


@dataclass(frozen=True)
class ListAssessmentsResponse:
    """Response containing a paginated list of assessment summaries."""

    items: tuple[AssessmentSummary, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True)
class GetAssessmentRequest:
    """Request to fetch a single assessment's full details."""

    assessment_id: str


@dataclass(frozen=True)
class FindingView:
    """Read-only view of a single finding."""

    finding_id: str
    title: str
    severity: str
    status: str
    evidence_count: int
    recommendation_count: int

    @classmethod
    def from_domain(cls, finding: Finding) -> FindingView:
        """Map a domain Finding entity to a boundary-safe view."""
        return cls(
            finding_id=str(finding.id),
            title=finding.title,
            severity=finding.severity.label,
            status=finding.status.value,
            evidence_count=len(finding.evidence),
            recommendation_count=len(finding.recommendations),
        )


@dataclass(frozen=True)
class AssessmentView:
    """Full assessment view including findings."""

    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str
    findings: tuple[FindingView, ...]

    @classmethod
    def from_domain(cls, assessment: Assessment) -> AssessmentView:
        """Map a domain Assessment aggregate to a boundary-safe detail view."""
        return cls(
            assessment_id=str(assessment.id),
            target=str(assessment.target),
            status=assessment.status.value,
            is_authorized=assessment.is_authorized,
            created_at=assessment.created_at.isoformat(),
            findings=tuple(FindingView.from_domain(f) for f in assessment.findings),
        )


@dataclass(frozen=True)
class StartAssessmentRequest:
    """Request to begin an authorized assessment."""

    assessment_id: str


@dataclass(frozen=True)
class StartAssessmentResponse:
    """Response from starting an assessment."""

    assessment_id: str
    status: str
    findings_count: int
    highest_severity: str | None


@dataclass(frozen=True)
class SubmitAssessmentRequest:
    """Request to submit an assessment for background execution."""

    assessment_id: str


@dataclass(frozen=True)
class SubmitAssessmentResponse:
    """Response from submitting an assessment for background execution."""

    assessment_id: str
    status: str
    job_id: str


@dataclass(frozen=True)
class CancelAssessmentRequest:
    """Request to cancel a running or authorized assessment."""

    assessment_id: str


@dataclass(frozen=True)
class CancelAssessmentResponse:
    """Response from cancelling an assessment."""

    assessment_id: str
    status: str


@dataclass(frozen=True)
class DeleteAssessmentRequest:
    """Request to permanently delete an assessment."""

    assessment_id: str


@dataclass(frozen=True)
class DeleteAssessmentResponse:
    """Response from deleting an assessment."""

    assessment_id: str


# ── Report DTOs ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RenderedReport:
    """A rendered report ready for delivery."""

    content: bytes
    media_type: str
    filename: str


@dataclass(frozen=True)
class GenerateReportRequest:
    """Request to generate a report for an assessment."""

    assessment_id: str


@dataclass(frozen=True)
class GenerateReportResponse:
    """Response from report generation."""

    assessment_id: str
    verdict: str
    action_required: bool
    highest_severity: str | None
    total_findings: int
    severity_counts: tuple[SeverityCount, ...]
    artifact_media_type: str
    artifact_filename: str
    artifact_bytes: int
