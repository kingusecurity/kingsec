from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from kingsec.application.compliance import (
    ComplianceCoverageCalculator,
    ComplianceGapAnalyzer,
    ComplianceMapper,
    ComplianceReportGenerator,
)
from kingsec.domain.compliance import ComplianceFramework
from kingsec.domain.enums import FindingStatus, Severity
from kingsec.domain.finding import Finding
from kingsec.domain.identifiers import FindingId

from .auth import CurrentUser, get_current_user, require_analyst
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["compliance"])


def _get_mapper(request: Request) -> ComplianceMapper:
    app: Application = get_application(request)
    svc = app.resolve(ComplianceMapper)
    if svc is None:
        raise HTTPException(status_code=500, detail="ComplianceMapper not available")
    return cast(ComplianceMapper, svc)


def _get_coverage_calc(request: Request) -> ComplianceCoverageCalculator:
    app: Application = get_application(request)
    svc = app.resolve(ComplianceCoverageCalculator)
    if svc is None:
        raise HTTPException(status_code=500, detail="ComplianceCoverageCalculator not available")
    return cast(ComplianceCoverageCalculator, svc)


def _get_gap_analyzer(request: Request) -> ComplianceGapAnalyzer:
    app: Application = get_application(request)
    svc = app.resolve(ComplianceGapAnalyzer)
    if svc is None:
        raise HTTPException(status_code=500, detail="ComplianceGapAnalyzer not available")
    return cast(ComplianceGapAnalyzer, svc)


def _get_report_generator(request: Request) -> ComplianceReportGenerator:
    app: Application = get_application(request)
    svc = app.resolve(ComplianceReportGenerator)
    if svc is None:
        raise HTTPException(status_code=500, detail="ComplianceReportGenerator not available")
    return cast(ComplianceReportGenerator, svc)


def _resolve(request: Request, cls: type) -> Any:
    app: Application = get_application(request)
    return app.resolve(cls)


def _record_audit(request: Request, action: Any, **kwargs: Any) -> None:
    """Record an audit entry, best-effort.

    Matches the non-fatal audit-publish pattern used everywhere else in the
    application layer: a failure here must never take down an otherwise
    successful request.
    """
    from kingsec.application.ports.outbound import AuditPublisher
    from kingsec.domain.audit import AuditEntry

    try:
        audit = _resolve(request, AuditPublisher)
        audit.record(AuditEntry(action=action, **kwargs))
    except Exception:
        import logging

        logging.getLogger(__name__).warning("audit publish failed (best-effort)", exc_info=True)


@router.get("/compliance/frameworks")
async def list_frameworks(
    user: CurrentUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return [
        {
            "id": fw.value,
            "name": fw.name.replace("_", " ").title(),
            "mapping_only": fw in (ComplianceFramework.ISO_27001, ComplianceFramework.PCI_DSS_4),
        }
        for fw in ComplianceFramework
    ]


@router.get("/compliance/frameworks/{framework_id}/controls")
async def get_framework_controls(
    framework_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    try:
        framework = ComplianceFramework(framework_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework_id}") from None
    mapper = _get_mapper(request)
    controls = mapper.get_framework_controls(framework)
    return [
        {
            "control_id": str(c.control_id),
            "title": c.title,
            "description": c.description,
            "category": c.category,
            "framework": c.framework.value,
        }
        for c in controls
    ]


@router.post("/compliance/map")
async def map_findings(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    findings_data = body.get("findings", [])
    findings = []
    for fd in findings_data:
        try:
            severity = Severity[fd.get("severity", "MEDIUM").upper()]
        except KeyError:
            severity = Severity.MEDIUM
        try:
            status = FindingStatus[fd.get("status", "OPEN").upper()]
        except KeyError:
            status = FindingStatus.OPEN
        f = Finding.reconstitute(
            finding_id=FindingId(fd.get("id", "unknown")),
            title=fd.get("title", ""),
            description=fd.get("description", ""),
            severity=severity,
            status=status,
            discovered_at=datetime.now(UTC),
        )
        findings.append(f)

    mapper = _get_mapper(request)
    mappings = mapper.map_all(findings)
    return {
        "mappings": [
            {
                "finding_id": m.finding_id,
                "finding_title": m.finding_title,
                "severity": m.severity,
                "controls": [
                    {
                        "framework": c.framework.value,
                        "control_id": str(c.control_id),
                        "title": c.title,
                        "category": c.category,
                    }
                    for c in m.controls
                ],
            }
            for m in mappings
        ],
        "total_mappings": sum(len(m.controls) for m in mappings),
    }


@router.post("/compliance/coverage")
async def calculate_coverage(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    mappings = _parse_mappings(body.get("mappings", []))
    frameworks_param = body.get("frameworks")
    enabled: list[ComplianceFramework] | None = None
    if frameworks_param:
        try:
            enabled = [ComplianceFramework(fw) for fw in frameworks_param]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid framework ID in list") from None

    calc = _get_coverage_calc(request)
    coverages = calc.calculate(mappings, enabled)
    return [
        {
            "framework": fc.framework.value,
            "total_controls": fc.total_controls,
            "passed": fc.passed,
            "failed": fc.failed,
            "not_assessed": fc.not_assessed,
            "coverage_percent": fc.coverage_percent,
        }
        for fc in coverages
    ]


@router.post("/compliance/gaps")
async def analyze_gaps(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    framework_id = body.get("framework")
    if not framework_id:
        raise HTTPException(status_code=400, detail="framework is required")
    try:
        framework = ComplianceFramework(framework_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework_id}") from None

    mappings = _parse_mappings(body.get("mappings", []))
    analyzer = _get_gap_analyzer(request)
    gaps = analyzer.analyze(framework, mappings)
    return {
        "framework": framework.value,
        "total_gaps": len(gaps),
        "gaps": [
            {
                "control_id": str(g.control.control_id),
                "title": g.control.title,
                "category": g.control.category,
                "status": g.status.value,
                "recommendation": g.recommendation,
            }
            for g in gaps
        ],
    }


@router.post("/compliance/report")
async def generate_compliance_report(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    assessment_id = body.get("assessment_id", "unknown")
    target = body.get("target", "")
    report_type = body.get("type", "executive")

    frameworks_param = body.get("frameworks")
    enabled: list[ComplianceFramework] | None = None
    if frameworks_param:
        try:
            enabled = [ComplianceFramework(fw) for fw in frameworks_param]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid framework ID in list") from None

    mappings = _parse_mappings(body.get("mappings", []))
    generator = _get_report_generator(request)
    report = generator.generate(
        assessment_id=assessment_id,
        target=target,
        mappings=mappings,
        enabled_frameworks=enabled,
    )

    if report_type == "technical":
        result = generator.generate_technical(report)
    elif report_type == "gap_remediation":
        result = generator.generate_gap_remediation(report)
    else:
        result = generator.generate_executive(report)

    from kingsec.domain.audit import AuditAction

    _record_audit(
        request,
        action=AuditAction.COMPLIANCE_REPORT_GENERATED,
        resource_type="compliance_report",
        resource_id=report.id,
        user_id=user.user_id,
        username=user.username,
        metadata={"assessment_id": assessment_id, "report_type": report_type},
    )

    return result


@router.get("/compliance/report/{report_id}/export")
async def export_compliance_report(
    report_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    from kingsec.domain.audit import AuditAction

    _record_audit(
        request,
        action=AuditAction.COMPLIANCE_EXPORTED,
        resource_type="compliance_report",
        resource_id=report_id,
        user_id=user.user_id,
        username=user.username,
    )
    return {
        "report_id": report_id,
        "exported_at": "now",
        "format": "json",
        "status": "exported",
    }


def _parse_mappings(mappings_data: list[dict[str, Any]]) -> list[Any]:
    from kingsec.domain.compliance import ControlId, FindingControlMapping, FrameworkControl

    mappings = []
    for md in mappings_data:
        controls = []
        for cd in md.get("controls", []):
            try:
                fw = ComplianceFramework(cd["framework"])
            except (ValueError, KeyError):
                continue
            controls.append(
                FrameworkControl(
                    framework=fw,
                    control_id=ControlId(cd["control_id"]),
                    title=cd.get("title", ""),
                    description=cd.get("description", ""),
                    category=cd.get("category", ""),
                )
            )
        mappings.append(
            FindingControlMapping(
                finding_id=md.get("finding_id", ""),
                finding_title=md.get("finding_title", ""),
                severity=md.get("severity", ""),
                controls=tuple(controls),
            )
        )
    return mappings
