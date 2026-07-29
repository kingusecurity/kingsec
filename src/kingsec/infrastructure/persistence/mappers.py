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
from kingsec.domain.job import (
    DeadLetterEntry,
    JobLease,
    JobQueueEntry,
    JobState,
    WorkerCapability,
    WorkerNode,
    WorkerStatus,
)
from kingsec.domain.playbook import (
    ActionExecutionLog,
    ExecutionHistory,
    Playbook,
    PlaybookAction,
    PlaybookTrigger,
)

from .models import (
    AlertModel,
    AssessmentORM,
    AssetModel,
    CopilotConversationModel,
    CveEntryModel,
    EvidenceORM,
    ExposureModel,
    FindingModel,
    FindingORM,
    ExecutionHistoryModel,
    InvestigationNoteModel,
    JobModel,
    MonitorEventModel,
    PlaybookModel,
    RecommendationORM,
    ReportORM,
    DeadLetterEntryModel,
    JobLeaseModel,
    JobQueueEntryModel,
    RuleModel,
    ScanModel,
    ThreatFeedModel,
    WorkerModel,
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
        organization_id=assessment.organization_id,
        team_id=assessment.team_id,
        owner_id=assessment.owner_id,
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
            report.verdict.highest_severity.name if report.verdict.highest_severity is not None else None
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
        severity_counts=[[severity.name, count] for severity, count in report.severity_counts],
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

    a = Assessment.reconstitute(
        assessment_id=AssessmentId(orm.id),
        target=Target(orm.target_value, TargetType[orm.target_type]),
        status=AssessmentStatus[orm.status],
        created_at=datetime.fromisoformat(orm.created_at),
        authorization=authorization,
        failure_reason=orm.failure_reason,
        findings=findings,
    )
    if orm.organization_id or orm.team_id or orm.owner_id:
        a.set_ownership(
            owner_id=orm.owner_id or "",
            organization_id=orm.organization_id,
            team_id=orm.team_id,
        )
    return a


def report_to_domain(orm: ReportORM) -> Report:
    """Rebuild a domain Report snapshot from a ReportORM row."""
    verdict = Verdict(
        highest_severity=(Severity[orm.verdict_highest_severity] if orm.verdict_highest_severity is not None else None),
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
    severity_counts = tuple((Severity[name], count) for name, count in orm.severity_counts)
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


# ===========================================================================
#  Extended Asset Inventory mappers  (Phase 18)
# ===========================================================================

from kingsec.domain.asset import Asset as DomainAsset
from kingsec.domain.identifiers import AssetId


def inventory_asset_to_orm(asset: DomainAsset) -> AssetModel:
    """Map a domain ``Asset`` entity to an ``AssetModel`` ORM row."""
    import json

    return AssetModel(
        id=str(asset.id),
        asset_type=asset.asset_type.value,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        domain=asset.domain,
        fqdn=asset.fqdn,
        mac_address=asset.mac_address,
        operating_system=asset.operating_system,
        os_version=asset.os_version,
        owner=asset.owner,
        criticality=asset.criticality.value,
        location=asset.location,
        description=asset.description,
        open_ports=json.dumps(asset.open_ports) if asset.open_ports else None,
        certificate_issuer=asset.certificate_issuer,
        certificate_expiry=asset.certificate_expiry,
        tls_version=asset.tls_version,
        cloud_provider=asset.cloud_provider,
        cloud_region=asset.cloud_region,
        container_runtime=asset.container_runtime,
        container_image=asset.container_image,
        database_type=asset.database_type,
        database_version=asset.database_version,
        web_server=asset.web_server,
        programming_language=asset.programming_language,
        framework=asset.framework,
        cms=asset.cms,
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        risk_score=asset.risk_score,
        metadata_json=json.dumps(asset.metadata) if asset.metadata else None,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


# ===========================================================================
#  Attack Surface mappers  (Phase 19)
# ===========================================================================

from kingsec.domain.attack_surface import Exposure as DomainExposure
from kingsec.domain.attack_surface import ExposureDetail, ExposureSeverity, ExposureStatus, ExposureType
from kingsec.domain.identifiers import AttackSurfaceId


def exposure_to_orm(exposure: DomainExposure) -> ExposureModel:
    import json
    return ExposureModel(
        id=str(exposure.id),
        asset_id=exposure.asset_id,
        exposure_type=exposure.exposure_type.value,
        severity=exposure.severity.value,
        title=exposure.title,
        description=exposure.description,
        detail_json=json.dumps([{"key": d.key, "value": d.value, "metadata": d.metadata} for d in exposure.detail]) if exposure.detail else None,
        status=exposure.status.value,
        source=exposure.source,
        port=exposure.port,
        protocol=exposure.protocol,
        hostname=exposure.hostname,
        ip_address=exposure.ip_address,
        domain=exposure.domain,
        url=exposure.url,
        tls_version=exposure.tls_version,
        certificate_issuer=exposure.certificate_issuer,
        certificate_expiry=exposure.certificate_expiry,
        header_name=exposure.header_name,
        header_value=exposure.header_value,
        technology_name=exposure.technology_name,
        technology_version=exposure.technology_version,
        cloud_provider=exposure.cloud_provider,
        cloud_bucket=exposure.cloud_bucket,
        evidence=exposure.evidence,
        remediation=exposure.remediation,
        risk_score=exposure.risk_score,
        metadata_json=json.dumps(exposure.metadata) if exposure.metadata else None,
        first_seen=exposure.first_seen,
        last_seen=exposure.last_seen,
        created_at=exposure.created_at,
        updated_at=exposure.updated_at,
    )


def exposure_to_domain(orm: ExposureModel) -> DomainExposure:
    import json
    detail: list[ExposureDetail] = []
    if orm.detail_json:
        try:
            raw = json.loads(orm.detail_json)
            detail = [ExposureDetail(key=d["key"], value=d["value"], metadata=d.get("metadata", {})) for d in raw]
        except (json.JSONDecodeError, TypeError):
            pass
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainExposure(
        AttackSurfaceId(orm.id),
        orm.asset_id,
        ExposureType(orm.exposure_type),
        severity=ExposureSeverity(orm.severity),
        title=orm.title,
        description=orm.description,
        detail=detail,
        status=ExposureStatus(orm.status),
        source=orm.source,
        port=orm.port,
        protocol=orm.protocol,
        hostname=orm.hostname,
        ip_address=orm.ip_address,
        domain=orm.domain,
        url=orm.url,
        tls_version=orm.tls_version,
        certificate_issuer=orm.certificate_issuer,
        certificate_expiry=orm.certificate_expiry,
        header_name=orm.header_name,
        header_value=orm.header_value,
        technology_name=orm.technology_name,
        technology_version=orm.technology_version,
        cloud_provider=orm.cloud_provider,
        cloud_bucket=orm.cloud_bucket,
        evidence=orm.evidence,
        remediation=orm.remediation,
        risk_score=orm.risk_score,
        metadata=metadata,
        first_seen=orm.first_seen,
        last_seen=orm.last_seen,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def inventory_asset_to_domain(orm: AssetModel) -> DomainAsset:
    """Rebuild a domain ``Asset`` entity from an ``AssetModel`` row."""
    import json

    from kingsec.domain.asset import (
        AssetCriticality,
        AssetService,
        AssetTag,
        AssetType,
        TechnologyFingerprint,
    )

    tags = [AssetTag(key=t.key, value=t.value) for t in (orm.tags or [])]
    technologies = [
        TechnologyFingerprint(
            technology_type=t.technology_type,
            name=t.name,
            version=t.version,
            vendor=t.vendor,
            confidence=t.confidence,
        )
        for t in (orm.technologies or [])
    ]
    services: list[AssetService] = []
    open_ports: list[int] = []
    if orm.open_ports:
        try:
            open_ports = json.loads(orm.open_ports)
        except (json.JSONDecodeError, TypeError):
            pass
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass

    return DomainAsset(
        AssetId(orm.id),
        AssetType(orm.asset_type),
        hostname=orm.hostname,
        ip_address=orm.ip_address,
        domain=orm.domain,
        fqdn=orm.fqdn,
        mac_address=orm.mac_address,
        operating_system=orm.operating_system,
        os_version=orm.os_version,
        criticality=AssetCriticality(orm.criticality) if orm.criticality else AssetCriticality.MEDIUM,
        owner=orm.owner,
        location=orm.location,
        description=orm.description,
        tags=tags,
        services=services,
        technologies=technologies,
        open_ports=open_ports,
        certificate_issuer=orm.certificate_issuer,
        certificate_expiry=orm.certificate_expiry,
        tls_version=orm.tls_version,
        cloud_provider=orm.cloud_provider,
        cloud_region=orm.cloud_region,
        container_runtime=orm.container_runtime,
        container_image=orm.container_image,
        database_type=orm.database_type,
        database_version=orm.database_version,
        web_server=orm.web_server,
        programming_language=orm.programming_language,
        framework=orm.framework,
        cms=orm.cms,
        first_seen=orm.first_seen,
        last_seen=orm.last_seen,
        risk_score=orm.risk_score,
        metadata=metadata,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


# ===========================================================================
#  Continuous Monitoring mappers  (Phase 20)
# ===========================================================================

from kingsec.domain.identifiers import AlertId, MonitorEventId, RuleId
from kingsec.domain.monitoring import (
    Alert as DomainAlert,
    AlertSeverity,
    AlertStatus,
    MonitorEvent as DomainMonitorEvent,
    MonitorEventContext,
    MonitorEventType,
    Rule as DomainRule,
    RuleCondition,
    RuleConditionOperator,
)


def monitor_event_to_orm(event: DomainMonitorEvent) -> MonitorEventModel:
    import json
    return MonitorEventModel(
        id=str(event.id),
        event_type=event.event_type.value,
        asset_id=event.asset_id,
        assessment_id=event.assessment_id,
        source=event.source,
        title=event.title,
        description=event.description,
        severity=event.severity.value,
        context_json=json.dumps([{"key": c.key, "value": c.value, "previous_value": c.previous_value, "metadata": c.metadata} for c in event.context]) if event.context else None,
        metadata_json=json.dumps(event.metadata) if event.metadata else None,
        timestamp=event.timestamp,
    )


def monitor_event_to_domain(orm: MonitorEventModel) -> DomainMonitorEvent:
    import json
    context: list[MonitorEventContext] = []
    if orm.context_json:
        try:
            raw = json.loads(orm.context_json)
            context = [MonitorEventContext(key=c["key"], value=c["value"], previous_value=c.get("previous_value"), metadata=c.get("metadata", {})) for c in raw]
        except (json.JSONDecodeError, TypeError):
            pass
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainMonitorEvent(
        MonitorEventId(orm.id),
        MonitorEventType(orm.event_type),
        asset_id=orm.asset_id,
        assessment_id=orm.assessment_id,
        source=orm.source,
        title=orm.title,
        description=orm.description,
        context=context,
        severity=AlertSeverity(orm.severity),
        metadata=metadata,
        timestamp=orm.timestamp,
    )


def alert_to_orm(alert: DomainAlert) -> AlertModel:
    import json
    return AlertModel(
        id=str(alert.id),
        rule_id=alert.rule_id,
        title=alert.title,
        description=alert.description,
        severity=alert.severity.value,
        status=alert.status.value,
        source_event_id=alert.source_event_id,
        asset_id=alert.asset_id,
        assessment_id=alert.assessment_id,
        metadata_json=json.dumps(alert.metadata) if alert.metadata else None,
        created_at=alert.created_at,
        acknowledged_at=alert.acknowledged_at,
        resolved_at=alert.resolved_at,
        acknowledged_by=alert.acknowledged_by,
        resolved_by=alert.resolved_by,
    )


def alert_to_domain(orm: AlertModel) -> DomainAlert:
    import json
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainAlert(
        AlertId(orm.id),
        orm.rule_id,
        title=orm.title,
        description=orm.description,
        severity=AlertSeverity(orm.severity),
        status=AlertStatus(orm.status),
        source_event_id=orm.source_event_id,
        asset_id=orm.asset_id,
        assessment_id=orm.assessment_id,
        metadata=metadata,
        created_at=orm.created_at,
        acknowledged_at=orm.acknowledged_at,
        resolved_at=orm.resolved_at,
        acknowledged_by=orm.acknowledged_by,
        resolved_by=orm.resolved_by,
    )


def rule_to_orm(rule: DomainRule) -> RuleModel:
    import json
    return RuleModel(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        event_type=rule.event_type.value if rule.event_type else None,
        conditions_json=json.dumps([{"field": c.field, "operator": c.operator.value, "value": c.value} for c in rule.conditions]) if rule.conditions else None,
        alert_severity=rule.alert_severity.value,
        alert_title_template=rule.alert_title_template,
        alert_description_template=rule.alert_description_template,
        enabled=rule.enabled,
        cooldown_minutes=rule.cooldown_minutes,
        notify_channels_json=json.dumps(list(rule.notify_channels)) if rule.notify_channels else None,
        metadata_json=json.dumps(rule.metadata) if rule.metadata else None,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def rule_to_domain(orm: RuleModel) -> DomainRule:
    import json
    conditions: list[RuleCondition] = []
    if orm.conditions_json:
        try:
            raw = json.loads(orm.conditions_json)
            conditions = [RuleCondition(field=c["field"], operator=RuleConditionOperator(c["operator"]), value=c["value"]) for c in raw]
        except (json.JSONDecodeError, TypeError):
            pass
    notify_channels: list[str] = []
    if orm.notify_channels_json:
        try:
            notify_channels = json.loads(orm.notify_channels_json)
        except (json.JSONDecodeError, TypeError):
            pass
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainRule(
        RuleId(orm.id),
        orm.name,
        description=orm.description,
        event_type=MonitorEventType(orm.event_type) if orm.event_type else None,
        conditions=conditions,
        alert_severity=AlertSeverity(orm.alert_severity),
        alert_title_template=orm.alert_title_template,
        alert_description_template=orm.alert_description_template,
        enabled=orm.enabled,
        cooldown_minutes=orm.cooldown_minutes,
        notify_channels=notify_channels,
        metadata=metadata,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


# --- Threat Intelligence -----------------------------------------------------


from kingsec.domain.threat_intelligence import (
    AffectedProduct,
    CveEntry as DomainCveEntry,
    CveReference,
    CvssData,
    EpssData,
    ExploitMaturity,
    KevEntry,
    ThreatFeedEntry as DomainThreatFeedEntry,
    ThreatFeedType,
)
from kingsec.domain.identifiers import CveId, ThreatFeedId


def cve_entry_to_orm(entry: DomainCveEntry) -> CveEntryModel:
    import json
    cvss = entry.cvss_data
    cvss_json = json.dumps({
        "version": cvss.version,
        "vector_string": cvss.vector_string,
        "base_score": cvss.base_score,
        "base_severity": cvss.base_severity,
        "exploitability_score": cvss.exploitability_score,
        "impact_score": cvss.impact_score,
        "attack_vector": cvss.attack_vector.value if cvss.attack_vector else None,
        "attack_complexity": cvss.attack_complexity.value if cvss.attack_complexity else None,
        "privileges_required": cvss.privileges_required.value if cvss.privileges_required else None,
        "user_interaction": cvss.user_interaction.value if cvss.user_interaction else None,
        "confidentiality_impact": cvss.confidentiality_impact.value if cvss.confidentiality_impact else None,
        "integrity_impact": cvss.integrity_impact.value if cvss.integrity_impact else None,
        "availability_impact": cvss.availability_impact.value if cvss.availability_impact else None,
    }) if entry.cvss_data else None
    epss_json = json.dumps({
        "score": entry.epss_data.score,
        "percentile": entry.epss_data.percentile,
        "model_version": entry.epss_data.model_version,
        "date": entry.epss_data.date,
    }) if entry.epss_data else None
    products_json = json.dumps([{
        "vendor": p.vendor, "product": p.product, "version": p.version, "operator": p.operator
    } for p in entry.affected_products]) if entry.affected_products else None
    refs_json = json.dumps([{
        "url": r.url, "source": r.source, "tags": list(r.tags)
    } for r in entry.references]) if entry.references else None
    advisories_json = json.dumps(list(entry.vendor_advisories)) if entry.vendor_advisories else None
    weaknesses_json = json.dumps(list(entry.weaknesses)) if entry.weaknesses else None
    kev_json = json.dumps({
        "id": entry.kev_entry.id,
        "cve_id": entry.kev_entry.cve_id,
        "vendor_project": entry.kev_entry.vendor_project,
        "product": entry.kev_entry.product,
        "vulnerability_name": entry.kev_entry.vulnerability_name,
        "date_added": entry.kev_entry.date_added,
        "due_date": entry.kev_entry.due_date,
        "required_action": entry.kev_entry.required_action,
        "known_ransomware_campaign_use": entry.kev_entry.known_ransomware_campaign_use,
        "notes": entry.kev_entry.notes,
    }) if entry.kev_entry else None
    return CveEntryModel(
        id=str(entry.id),
        cve_code=entry.cve_code,
        description=entry.description,
        severity=entry.severity,
        published_date=entry.published_date,
        last_modified=entry.last_modified,
        cvss_data_json=cvss_json,
        epss_data_json=epss_json,
        exploit_maturity=entry.exploit_maturity.value,
        affected_products_json=products_json,
        references_json=refs_json,
        vendor_advisories_json=advisories_json,
        weaknesses_json=weaknesses_json,
        is_kev=entry.is_kev,
        kev_entry_json=kev_json,
        threat_score=entry.threat_score,
        exploitability_score=entry.exploitability_score,
        priority_score=entry.priority_score,
        metadata_json=None,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def cve_entry_to_domain(orm: CveEntryModel) -> DomainCveEntry:
    import json
    cvss = CvssData()
    if orm.cvss_data_json:
        try:
            d = json.loads(orm.cvss_data_json)
            cvss = CvssData(
                version=d.get("version", "3.1"),
                vector_string=d.get("vector_string", ""),
                base_score=float(d.get("base_score", 0)),
                base_severity=d.get("base_severity", "NONE"),
                exploitability_score=float(d.get("exploitability_score", 0)),
                impact_score=float(d.get("impact_score", 0)),
                attack_vector=AttackVector(d["attack_vector"]) if d.get("attack_vector") else None,
                attack_complexity=AttackComplexity(d["attack_complexity"]) if d.get("attack_complexity") else None,
                privileges_required=PrivilegesRequired(d["privileges_required"]) if d.get("privileges_required") else None,
                user_interaction=UserInteraction(d["user_interaction"]) if d.get("user_interaction") else None,
                confidentiality_impact=CiaImpact(d["confidentiality_impact"]) if d.get("confidentiality_impact") else None,
                integrity_impact=CiaImpact(d["integrity_impact"]) if d.get("integrity_impact") else None,
                availability_impact=CiaImpact(d["availability_impact"]) if d.get("availability_impact") else None,
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    epss = None
    if orm.epss_data_json:
        try:
            d = json.loads(orm.epss_data_json)
            epss = EpssData(
                score=float(d.get("score", 0)),
                percentile=float(d.get("percentile", 0)),
                model_version=d.get("model_version", ""),
                date=d.get("date", ""),
            )
        except (json.JSONDecodeError, TypeError):
            pass
    products = []
    if orm.affected_products_json:
        try:
            products = [AffectedProduct(**p) for p in json.loads(orm.affected_products_json)]
        except (json.JSONDecodeError, TypeError):
            pass
    refs = []
    if orm.references_json:
        try:
            refs = [CveReference(url=r.get("url", ""), source=r.get("source", ""), tags=tuple(r.get("tags", [])))
                    for r in json.loads(orm.references_json)]
        except (json.JSONDecodeError, TypeError):
            pass
    advisories: list[str] = []
    if orm.vendor_advisories_json:
        try:
            advisories = json.loads(orm.vendor_advisories_json)
        except (json.JSONDecodeError, TypeError):
            pass
    weaknesses: list[str] = []
    if orm.weaknesses_json:
        try:
            weaknesses = json.loads(orm.weaknesses_json)
        except (json.JSONDecodeError, TypeError):
            pass
    kev_entry = None
    if orm.kev_entry_json:
        try:
            d = json.loads(orm.kev_entry_json)
            kev_entry = KevEntry(**d)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainCveEntry(
        cve_id=CveId(orm.id),
        cve_code=orm.cve_code,
        description=orm.description,
        severity=orm.severity,
        published_date=orm.published_date,
        last_modified=orm.last_modified,
        cvss_data=cvss,
        epss_data=epss,
        exploit_maturity=ExploitMaturity(orm.exploit_maturity) if orm.exploit_maturity else ExploitMaturity.UNKNOWN,
        affected_products=products,
        references=refs,
        vendor_advisories=advisories,
        weaknesses=weaknesses,
        is_kev=orm.is_kev,
        kev_entry=kev_entry,
        threat_score=orm.threat_score,
        exploitability_score=orm.exploitability_score,
        priority_score=orm.priority_score,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def threat_feed_to_orm(feed: DomainThreatFeedEntry) -> ThreatFeedModel:
    import json
    return ThreatFeedModel(
        id=feed.feed_id,
        feed_type=feed.feed_type.value,
        title=feed.title,
        description=feed.description,
        source_url=feed.source_url,
        entries=feed.entries,
        last_synced=feed.last_synced,
        status=feed.status,
        metadata_json=json.dumps(feed.metadata) if feed.metadata else None,
    )


def threat_feed_to_domain(orm: ThreatFeedModel) -> DomainThreatFeedEntry:
    import json
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainThreatFeedEntry(
        feed_id=orm.id,
        feed_type=ThreatFeedType(orm.feed_type),
        title=orm.title,
        description=orm.description,
        source_url=orm.source_url,
        entries=orm.entries,
        last_synced=orm.last_synced,
        status=orm.status,
        metadata=metadata,
    )


from kingsec.domain.threat_intelligence import AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, CiaImpact


# --- AI Copilot -------------------------------------------------------------


import json

from kingsec.domain.copilot import CopilotConversation as DomainCopilotConversation, CopilotMessage, InvestigationNote as DomainInvestigationNote
from .models import CopilotConversationModel, InvestigationNoteModel


def copilot_conversation_to_orm(conv: DomainCopilotConversation) -> CopilotConversationModel:
    messages = [{"role": m.role, "content": m.content, "timestamp": m.timestamp} for m in conv.messages]
    return CopilotConversationModel(
        id=conv.id,
        title=conv.title,
        assessment_id=conv.assessment_id,
        finding_id=conv.finding_id,
        asset_id=conv.asset_id,
        cve_id=conv.cve_id,
        alert_id=conv.alert_id,
        exposure_id=conv.exposure_id,
        messages_json=json.dumps(messages) if messages else None,
        metadata_json=json.dumps(conv.metadata) if conv.metadata else None,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
    )


def copilot_conversation_to_domain(orm: CopilotConversationModel) -> DomainCopilotConversation:
    messages: list[CopilotMessage] = []
    if orm.messages_json:
        try:
            raw = json.loads(orm.messages_json)
            messages = [CopilotMessage(role=m.get("role", "user"), content=m.get("content", ""), timestamp=m.get("timestamp", "")) for m in raw]
        except (json.JSONDecodeError, TypeError):
            pass
    metadata: dict[str, object] = {}
    if orm.metadata_json:
        try:
            metadata = json.loads(orm.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainCopilotConversation(
        id=orm.id,
        title=orm.title,
        assessment_id=orm.assessment_id,
        finding_id=orm.finding_id,
        asset_id=orm.asset_id,
        cve_id=orm.cve_id,
        alert_id=orm.alert_id,
        exposure_id=orm.exposure_id,
        messages=tuple(messages),
        metadata=metadata,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def investigation_note_to_orm(note: DomainInvestigationNote) -> InvestigationNoteModel:
    return InvestigationNoteModel(
        id=note.id,
        conversation_id=note.conversation_id,
        content=note.content,
        author=note.author,
        pinned=note.pinned,
        assessment_id=note.assessment_id,
        finding_id=note.finding_id,
        tags_json=json.dumps(list(note.tags)) if note.tags else None,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


def investigation_note_to_domain(orm: InvestigationNoteModel) -> DomainInvestigationNote:
    tags: list[str] = []
    if orm.tags_json:
        try:
            tags = json.loads(orm.tags_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return DomainInvestigationNote(
        id=orm.id,
        conversation_id=orm.conversation_id,
        content=orm.content,
        author=orm.author,
        pinned=orm.pinned,
        assessment_id=orm.assessment_id,
        finding_id=orm.finding_id,
        tags=tuple(tags),
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


# ---------------------------------------------------------------------------
# Playbook mappers
# ---------------------------------------------------------------------------


def playbook_to_orm(playbook: Playbook) -> PlaybookModel:
    return PlaybookModel(
        id=playbook.id,
        name=playbook.name,
        description=playbook.description,
        category=playbook.category,
        severity=playbook.severity,
        tags_json=json.dumps(list(playbook.tags)),
        enabled=playbook.enabled,
        trigger_json=json.dumps({
            "trigger_type": playbook.trigger.trigger_type.value,
            "config": playbook.trigger.config,
            "conditions": playbook.trigger.conditions,
        }),
        actions_json=json.dumps([
            {
                "action_type": a.action_type.value,
                "config": a.config,
                "order": a.order,
                "timeout_seconds": a.timeout_seconds,
                "retry_count": a.retry_count,
                "continue_on_failure": a.continue_on_failure,
            }
            for a in playbook.actions
        ]),
        rollback_actions_json=json.dumps([
            {
                "action_type": a.action_type.value,
                "config": a.config,
                "order": a.order,
                "timeout_seconds": a.timeout_seconds,
                "retry_count": a.retry_count,
                "continue_on_failure": a.continue_on_failure,
            }
            for a in playbook.rollback_actions
        ]),
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
    )


def playbook_to_domain(orm: PlaybookModel) -> Playbook:
    from kingsec.domain.playbook import PlaybookActionType, PlaybookTriggerType
    trigger_data = json.loads(orm.trigger_json) if orm.trigger_json else {}
    actions_data = json.loads(orm.actions_json) if orm.actions_json else []
    rollback_data = json.loads(orm.rollback_actions_json) if orm.rollback_actions_json else []
    tags: list[str] = []
    if orm.tags_json:
        try:
            tags = json.loads(orm.tags_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return Playbook(
        playbook_id=orm.id,
        name=orm.name,
        description=orm.description,
        category=orm.category,
        severity=orm.severity,
        tags=tags,
        enabled=orm.enabled,
        trigger=PlaybookTrigger(
            trigger_type=PlaybookTriggerType(trigger_data.get("trigger_type", "manual")),
            config=trigger_data.get("config", {}),
            conditions=trigger_data.get("conditions", {}),
        ),
        actions=[
            PlaybookAction(
                action_type=PlaybookActionType(a["action_type"]),
                config=a.get("config", {}),
                order=a.get("order", i),
                timeout_seconds=a.get("timeout_seconds", 60),
                retry_count=a.get("retry_count", 0),
                continue_on_failure=a.get("continue_on_failure", False),
            )
            for i, a in enumerate(actions_data)
        ],
        rollback_actions=[
            PlaybookAction(
                action_type=PlaybookActionType(a["action_type"]),
                config=a.get("config", {}),
                order=a.get("order", i),
                timeout_seconds=a.get("timeout_seconds", 60),
                retry_count=a.get("retry_count", 0),
                continue_on_failure=a.get("continue_on_failure", False),
            )
            for i, a in enumerate(rollback_data)
        ],
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def execution_history_to_orm(history: ExecutionHistory) -> ExecutionHistoryModel:
    return ExecutionHistoryModel(
        id=history.id,
        playbook_id=history.playbook_id,
        playbook_name=history.playbook_name,
        trigger_type=history.trigger_type,
        trigger_entity_id=history.trigger_entity_id,
        status=history.status.value,
        action_logs_json=json.dumps([
            {
                "action_type": l.action_type,
                "status": l.status,
                "started_at": l.started_at,
                "completed_at": l.completed_at,
                "duration_ms": l.duration_ms,
                "output": l.output,
                "error": l.error,
                "retry_attempts": l.retry_attempts,
            }
            for l in history.action_logs
        ]),
        started_at=history.started_at,
        completed_at=history.completed_at,
        duration_ms=history.duration_ms,
        error=history.error,
        rolled_back=history.rolled_back,
        created_at=history.created_at,
    )


def execution_history_to_domain(orm: ExecutionHistoryModel) -> ExecutionHistory:
    logs: list[ActionExecutionLog] = []
    if orm.action_logs_json:
        try:
            logs_data = json.loads(orm.action_logs_json)
            logs = [
                ActionExecutionLog(
                    action_type=l.get("action_type", ""),
                    status=l.get("status", ""),
                    started_at=l.get("started_at", ""),
                    completed_at=l.get("completed_at", ""),
                    duration_ms=l.get("duration_ms", 0),
                    output=l.get("output", ""),
                    error=l.get("error", ""),
                    retry_attempts=l.get("retry_attempts", 0),
                )
                for l in logs_data
            ]
        except (json.JSONDecodeError, TypeError):
            pass
    from kingsec.domain.playbook import ExecutionStatus
    return ExecutionHistory(
        id=orm.id,
        playbook_id=orm.playbook_id,
        playbook_name=orm.playbook_name,
        trigger_type=orm.trigger_type,
        trigger_entity_id=orm.trigger_entity_id,
        status=ExecutionStatus(orm.status),
        action_logs=tuple(logs),
        started_at=orm.started_at,
        completed_at=orm.completed_at or "",
        duration_ms=orm.duration_ms,
        error=orm.error,
        rolled_back=orm.rolled_back,
        created_at=orm.created_at,
    )


def worker_to_orm(worker: WorkerNode) -> WorkerModel:
    return WorkerModel(
        worker_id=worker.worker_id,
        hostname=worker.hostname,
        os=worker.os,
        cpu=worker.cpu,
        ram_mb=worker.ram_mb,
        capabilities_json=json.dumps([{"scanner_id": c.scanner_id, "scanner_name": c.scanner_name, "scanner_version": c.scanner_version} for c in worker.capabilities]),
        current_jobs_json=json.dumps(list(worker.current_jobs)),
        health=worker.health,
        last_heartbeat=worker.last_heartbeat,
        status=worker.status.value,
        created_at=worker.created_at,
        updated_at=worker.updated_at,
    )


def worker_to_domain(orm: WorkerModel) -> WorkerNode:
    caps = []
    if orm.capabilities_json:
        try:
            caps_data = json.loads(orm.capabilities_json)
            caps = [WorkerCapability(**c) for c in caps_data]
        except (json.JSONDecodeError, TypeError):
            pass
    current = []
    if orm.current_jobs_json:
        try:
            current = json.loads(orm.current_jobs_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return WorkerNode(
        worker_id=orm.worker_id,
        hostname=orm.hostname,
        os=orm.os,
        cpu=orm.cpu,
        ram_mb=orm.ram_mb,
        capabilities=tuple(caps),
        current_jobs=tuple(current),
        health=orm.health,
        last_heartbeat=orm.last_heartbeat,
        status=WorkerStatus(orm.status),
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def job_queue_entry_to_orm(entry: JobQueueEntry) -> JobQueueEntryModel:
    return JobQueueEntryModel(
        entry_id=entry.entry_id,
        job_id=entry.job_id,
        state=entry.state.value,
        payload=entry.payload,
        target=entry.target,
        scanner_ids_json=json.dumps(list(entry.scanner_ids)),
        assigned_worker_id=entry.assigned_worker_id,
        retry_count=entry.retry_count,
        max_retries=entry.max_retries,
        error_message=entry.error_message,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
        started_at=entry.started_at,
        completed_at=entry.completed_at,
    )


def job_queue_entry_to_domain(orm: JobQueueEntryModel) -> JobQueueEntry:
    scanner_ids = []
    if orm.scanner_ids_json:
        try:
            scanner_ids = json.loads(orm.scanner_ids_json)
        except (json.JSONDecodeError, TypeError):
            pass
    return JobQueueEntry(
        entry_id=orm.entry_id,
        job_id=orm.job_id,
        state=JobState(orm.state),
        payload=orm.payload,
        target=orm.target,
        scanner_ids=tuple(scanner_ids),
        assigned_worker_id=orm.assigned_worker_id,
        retry_count=orm.retry_count,
        max_retries=orm.max_retries,
        error_message=orm.error_message,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
        started_at=orm.started_at,
        completed_at=orm.completed_at,
    )


def job_lease_to_orm(lease: JobLease) -> JobLeaseModel:
    return JobLeaseModel(
        lease_id=lease.lease_id,
        job_id=lease.job_id,
        worker_id=lease.worker_id,
        acquired_at=lease.acquired_at,
        expires_at=lease.expires_at,
        renewed_at=lease.renewed_at,
        released_at=lease.released_at,
    )


def job_lease_to_domain(orm: JobLeaseModel) -> JobLease:
    return JobLease(
        lease_id=orm.lease_id,
        job_id=orm.job_id,
        worker_id=orm.worker_id,
        acquired_at=orm.acquired_at,
        expires_at=orm.expires_at,
        renewed_at=orm.renewed_at,
        released_at=orm.released_at,
    )


def dead_letter_to_orm(entry: DeadLetterEntry) -> DeadLetterEntryModel:
    return DeadLetterEntryModel(
        entry_id=entry.entry_id,
        original_job_id=entry.original_job_id,
        original_entry_id=entry.original_entry_id,
        reason=entry.reason,
        payload=entry.payload,
        target=entry.target,
        retry_count=entry.retry_count,
        failed_at=entry.failed_at,
        created_at=entry.created_at,
    )


def dead_letter_to_domain(orm: DeadLetterEntryModel) -> DeadLetterEntry:
    return DeadLetterEntry(
        entry_id=orm.entry_id,
        original_job_id=orm.original_job_id,
        original_entry_id=orm.original_entry_id,
        reason=orm.reason,
        payload=orm.payload,
        target=orm.target,
        retry_count=orm.retry_count,
        failed_at=orm.failed_at,
        created_at=orm.created_at,
    )
