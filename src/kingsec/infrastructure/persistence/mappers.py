"""The mapping layer between domain objects and ORM rows.

Pure translation functions — the heart of the Data Mapper pattern. ``*_to_orm``
functions build database rows from domain objects (for writing); ``*_to_domain``
functions rebuild domain objects from rows (reconstitution, for reading). No
SQLAlchemy session logic lives here; these are deterministic, easily unit-tested
transformations.

Timestamps cross the boundary as ISO-8601 strings; ``datetime.fromisoformat``
restores the timezone-aware value the domain requires.
"""

from __future__ import annotations

from datetime import datetime

from kingsec.domain import (
    Assessment,
    AssessmentId,
    AssessmentStatus,
    Authorization,
    Evidence,
    Finding,
    FindingId,
    FindingStatus,
    FindingSummary,
    Recommendation,
    Report,
    Severity,
    Target,
    TargetType,
    Verdict,
)

from .models import (
    AssessmentORM,
    EvidenceORM,
    FindingORM,
    RecommendationORM,
    ReportORM,
)

# --- domain -> ORM (for writing) ---------------------------------------------


def finding_to_orm(finding: Finding) -> FindingORM:
    """Build a FindingORM (with its children) from a domain Finding."""

    return FindingORM(
        id=str(finding.id),
        title=finding.title,
        description=finding.description,
        severity=finding.severity.name,
        status=finding.status.value,
        discovered_at=finding.discovered_at.isoformat(),
        evidence=[
            EvidenceORM(
                summary=item.summary,
                detail=item.detail,
                collected_at=item.collected_at.isoformat(),
            )
            for item in finding.evidence
        ],
        recommendations=[
            RecommendationORM(
                title=rec.title,
                description=rec.description,
                priority=rec.priority.name,
            )
            for rec in finding.recommendations
        ],
    )


def assessment_to_orm(assessment: Assessment) -> AssessmentORM:
    """Build an AssessmentORM aggregate (with findings) from a domain Assessment."""

    authorization = assessment.authorization
    return AssessmentORM(
        id=str(assessment.id),
        target_value=assessment.target.value,
        target_type=assessment.target.type.name,
        status=assessment.status.name,
        created_at=assessment.created_at.isoformat(),
        authorized_by=authorization.authorized_by if authorization else None,
        authorized_at=authorization.authorized_at.isoformat() if authorization else None,
        authorization_scope=authorization.scope if authorization else None,
        failure_reason=assessment.failure_reason,
        findings=[finding_to_orm(finding) for finding in assessment.findings],
    )


def report_to_orm(report: Report) -> ReportORM:
    """Build a ReportORM (with JSON entries) from a domain Report snapshot."""

    return ReportORM(
        assessment_id=report.assessment_id,
        target=report.target,
        generated_at=report.generated_at.isoformat(),
        verdict_headline=report.verdict.headline,
        verdict_action_required=report.verdict.action_required,
        verdict_highest_severity=(
            report.verdict.highest_severity.name
            if report.verdict.highest_severity is not None
            else None
        ),
        entries=[
            {
                "finding_id": entry.finding_id,
                "title": entry.title,
                "severity": entry.severity.name,
                "status": entry.status.value,
                "evidence_count": entry.evidence_count,
                "recommendation_count": entry.recommendation_count,
            }
            for entry in report.entries
        ],
        severity_counts=[
            [severity.name, count] for severity, count in report.severity_counts
        ],
    )


# --- ORM -> domain (reconstitution, for reading) -----------------------------


def finding_to_domain(orm: FindingORM) -> Finding:
    """Rebuild a domain Finding from a FindingORM row and its children."""

    evidence = [
        Evidence(
            summary=item.summary,
            detail=item.detail,
            collected_at=datetime.fromisoformat(item.collected_at),
        )
        for item in orm.evidence
    ]
    recommendations = [
        Recommendation(
            title=rec.title,
            description=rec.description,
            priority=Severity[rec.priority],
        )
        for rec in orm.recommendations
    ]
    return Finding.reconstitute(
        finding_id=FindingId(orm.id),
        title=orm.title,
        description=orm.description,
        severity=Severity[orm.severity],
        status=FindingStatus(orm.status),
        discovered_at=datetime.fromisoformat(orm.discovered_at),
        evidence=evidence,
        recommendations=recommendations,
    )


def assessment_to_domain(orm: AssessmentORM) -> Assessment:
    """Rebuild a domain Assessment aggregate from an AssessmentORM row."""

    authorization: Authorization | None = None
    if orm.authorized_by is not None:
        authorization = Authorization(
            authorized_by=orm.authorized_by,
            authorized_at=datetime.fromisoformat(orm.authorized_at or ""),
            scope=orm.authorization_scope or "",
        )

    # Deterministic order for findings on load (by discovery time, then id).
    ordered = sorted(orm.findings, key=lambda f: (f.discovered_at, f.id))
    findings = [finding_to_domain(f) for f in ordered]

    return Assessment.reconstitute(
        assessment_id=AssessmentId(orm.id),
        target=Target(orm.target_value, TargetType[orm.target_type]),
        status=AssessmentStatus[orm.status],
        created_at=datetime.fromisoformat(orm.created_at),
        authorization=authorization,
        failure_reason=orm.failure_reason,
        findings=findings,
    )


def report_to_domain(orm: ReportORM) -> Report:
    """Rebuild a domain Report snapshot from a ReportORM row."""

    verdict = Verdict(
        highest_severity=(
            Severity[orm.verdict_highest_severity]
            if orm.verdict_highest_severity is not None
            else None
        ),
        headline=orm.verdict_headline,
        action_required=orm.verdict_action_required,
    )
    entries = tuple(
        FindingSummary(
            finding_id=entry["finding_id"],
            title=entry["title"],
            severity=Severity[entry["severity"]],
            status=FindingStatus(entry["status"]),
            evidence_count=entry["evidence_count"],
            recommendation_count=entry["recommendation_count"],
        )
        for entry in orm.entries
    )
    severity_counts = tuple(
        (Severity[name], count) for name, count in orm.severity_counts
    )
    return Report(
        assessment_id=orm.assessment_id,
        target=orm.target,
        generated_at=datetime.fromisoformat(orm.generated_at),
        verdict=verdict,
        entries=entries,
        severity_counts=severity_counts,
    )
