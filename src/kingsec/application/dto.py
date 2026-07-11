"""Data Transfer Objects for the application boundary.

Why DTOs at all?
    Use cases must not accept or return *domain* objects across the boundary.
    If a web controller could hand a use case a half-built ``Assessment``, or
    receive one back and poke at it, the domain's encapsulation would leak out to
    the edges of the system. DTOs are flat, immutable bags of primitives: the
    caller speaks in strings and ints, and the use case owns the translation to
    and from domain types. All DTOs are frozen dataclasses.

Naming: ``*Request`` = input to a use case, ``*Response``/``*View`` = output.
``from_domain`` classmethods centralise the domain->DTO mapping.
"""

from __future__ import annotations

from dataclasses import dataclass

from kingsec.domain import Assessment, Finding

# --- CreateAssessment --------------------------------------------------------


@dataclass(frozen=True)
class CreateAssessmentRequest:
    target_value: str
    target_type: str          # e.g. "ip_address", "url" (mapped to TargetType)
    authorized_by: str        # who authorizes this assessment
    scope: str                # what is authorized (audit trail)


@dataclass(frozen=True)
class CreateAssessmentResponse:
    assessment_id: str
    status: str
    target: str


# --- StartAssessment ---------------------------------------------------------


@dataclass(frozen=True)
class StartAssessmentRequest:
    assessment_id: str


@dataclass(frozen=True)
class StartAssessmentResponse:
    assessment_id: str
    status: str
    findings_count: int
    highest_severity: str | None


# --- GetAssessment -----------------------------------------------------------


@dataclass(frozen=True)
class GetAssessmentRequest:
    assessment_id: str


@dataclass(frozen=True)
class FindingView:
    finding_id: str
    title: str
    severity: str
    status: str
    evidence_count: int
    recommendation_count: int

    @classmethod
    def from_domain(cls, finding: Finding) -> "FindingView":
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
    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str                       # ISO-8601 string, not a datetime
    findings: tuple[FindingView, ...]

    @classmethod
    def from_domain(cls, assessment: Assessment) -> "AssessmentView":
        return cls(
            assessment_id=str(assessment.id),
            target=str(assessment.target),
            status=assessment.status.value,
            is_authorized=assessment.is_authorized,
            created_at=assessment.created_at.isoformat(),
            findings=tuple(FindingView.from_domain(f) for f in assessment.findings),
        )


# --- GenerateReport ----------------------------------------------------------


@dataclass(frozen=True)
class GenerateReportRequest:
    assessment_id: str


@dataclass(frozen=True)
class SeverityCount:
    severity: str
    count: int


@dataclass(frozen=True)
class RenderedReport:
    """The output of a ReportGeneratorPort: a rendered deliverable artifact."""

    content: bytes
    media_type: str
    filename: str


@dataclass(frozen=True)
class GenerateReportResponse:
    assessment_id: str
    verdict: str
    action_required: bool
    highest_severity: str | None
    total_findings: int
    severity_counts: tuple[SeverityCount, ...]
    artifact_media_type: str
    artifact_filename: str
    artifact_bytes: int


# --- SubmitAssessment (async) ------------------------------------------------


@dataclass(frozen=True)
class SubmitAssessmentRequest:
    assessment_id: str


@dataclass(frozen=True)
class SubmitAssessmentResponse:
    assessment_id: str
    status: str
    job_id: str


# --- CancelAssessment --------------------------------------------------------


@dataclass(frozen=True)
class CancelAssessmentRequest:
    assessment_id: str


@dataclass(frozen=True)
class CancelAssessmentResponse:
    assessment_id: str
    status: str


# --- ListAssessments ---------------------------------------------------------


@dataclass(frozen=True)
class AssessmentSummary:
    """Lightweight view of an assessment (no findings) for list endpoints."""

    assessment_id: str
    target: str
    status: str
    is_authorized: bool
    created_at: str
    findings_count: int

    @classmethod
    def from_domain(cls, assessment: Assessment) -> "AssessmentSummary":
        return cls(
            assessment_id=str(assessment.id),
            target=str(assessment.target),
            status=assessment.status.value,
            is_authorized=assessment.is_authorized,
            created_at=assessment.created_at.isoformat(),
            findings_count=len(assessment.findings),
        )


@dataclass(frozen=True)
class ListAssessmentsRequest:
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class ListAssessmentsResponse:
    items: tuple[AssessmentSummary, ...]
    total: int
    limit: int
    offset: int


# --- DeleteAssessment --------------------------------------------------------


@dataclass(frozen=True)
class DeleteAssessmentRequest:
    assessment_id: str


@dataclass(frozen=True)
class DeleteAssessmentResponse:
    assessment_id: str
