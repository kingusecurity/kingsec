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

from kingsec.application.jobs import ScanJob
from kingsec.application.ports.repositories import Asset
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
    ScannerId,
    ScannerResult,
    Severity,
    Target,
    TargetType,
    Verdict,
)

from .models import (
    AssessmentORM,
    AssetModel,
    EvidenceORM,
    FindingModel,
    FindingORM,
    JobModel,
    RecommendationORM,
    ReportORM,
    ScanModel,
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


# ===========================================================================
#  ScannerResult ↔ ScanModel / FindingModel  (Phase 7.3.3)
# ===========================================================================


def scan_finding_to_orm(finding: Finding, scan_id: str) -> FindingModel:
    """Build a FindingModel row from a domain Finding for a scan result."""
    return FindingModel(
        id=str(finding.id),
        scan_id=scan_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.name,
        scanner=None,
        asset=None,
        created_at=finding.discovered_at.isoformat(),
    )


def scan_finding_to_domain(orm: FindingModel) -> Finding:
    """Rebuild a domain Finding from a FindingModel row (scan context)."""
    return Finding.reconstitute(
        finding_id=FindingId(orm.id),
        title=orm.title,
        description=orm.description,
        severity=Severity[orm.severity],
        status=FindingStatus.OPEN,
        discovered_at=datetime.fromisoformat(orm.created_at),
    )


def scan_result_to_orm(scan_id: str, result: ScannerResult) -> ScanModel:
    """Build a ScanModel from a scan id and ScannerResult."""
    now = datetime.now().isoformat()
    return ScanModel(
        id=scan_id,
        target=str(result.scanner_id),
        status="COMPLETED",
        created_at=now,
        completed_at=now,
        scanner_count=len(result.findings),
        findings=[scan_finding_to_orm(f, scan_id) for f in result.findings],
    )


def scan_result_to_domain(orm: ScanModel) -> ScannerResult:
    """Rebuild a ScannerResult from a ScanModel row and its findings.

    Note: ``raw_output``, ``duration_seconds``, ``scanner_version``, and
    ``warnings`` are not stored in the current ORM schema and are returned
    as empty / zero defaults.  A future migration can add columns for these.
    """
    return ScannerResult(
        scanner_id=ScannerId(orm.target),
        findings=tuple(scan_finding_to_domain(f) for f in orm.findings),
        raw_output="",
        duration_seconds=0.0,
    )


# ===========================================================================
#  ScanJob ↔ JobModel  (Phase 7.3.4)
# ===========================================================================


def job_to_orm(job: ScanJob) -> JobModel:
    """Build a JobModel row from a ScanJob record."""
    return JobModel(
        id=str(job.id),
        status=job.status.value,
        target=job.target,
        created_at=job.created_at.isoformat(),
        updated_at=job.updated_at.isoformat(),
    )


def job_to_domain(orm: JobModel) -> ScanJob:
    """Rebuild a ScanJob from a JobModel row.

    Note: ``config`` is not stored in the current ORM schema and is returned
    as ``{}``.  A future migration can add a column for it.
    """
    from kingsec.application.job import JobId
    from kingsec.application.jobs import JobStatus, ScanJob

    return ScanJob(
        id=JobId(orm.id),
        target=orm.target,
        config={},
        status=JobStatus(orm.status),
        created_at=datetime.fromisoformat(orm.created_at),
        updated_at=datetime.fromisoformat(orm.updated_at),
    )


# ===========================================================================
#  Asset ↔ AssetModel  (Phase 7.3.5)
# ===========================================================================


def _infer_target(orm: AssetModel) -> Target:
    """Rebuild a Target from whichever AssetModel column carries the value."""
    if orm.hostname:
        return Target(orm.hostname, TargetType.HOSTNAME)
    if orm.ip_address:
        return Target(orm.ip_address, TargetType.IP_ADDRESS)
    return Target(orm.id, TargetType.HOSTNAME)


def asset_to_orm(asset: Asset) -> AssetModel:
    """Build an AssetModel row from an Asset value object."""
    hostname = asset.target.value if asset.target.type == TargetType.HOSTNAME else None
    ip_address = asset.target.value if asset.target.type == TargetType.IP_ADDRESS else None

    return AssetModel(
        id=asset.id,
        hostname=hostname,
        ip_address=ip_address,
        created_at=asset.discovered_at.isoformat(),
    )


def asset_to_domain(orm: AssetModel) -> Asset:
    """Rebuild an Asset value object from an AssetModel row.

    Note: ``tags`` are not stored in the current ORM schema and are returned
    as an empty frozenset.  A future migration can add a column for them.
    """
    return Asset(
        id=orm.id,
        target=_infer_target(orm),
        discovered_at=datetime.fromisoformat(orm.created_at),
        tags=frozenset(),
    )
