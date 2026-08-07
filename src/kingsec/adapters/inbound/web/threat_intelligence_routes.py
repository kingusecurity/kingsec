from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from kingsec.application.errors import CveNotFoundError
from kingsec.application.threat_intelligence.ports import CveFilter, KevFilter
from kingsec.application.threat_intelligence.reports import ThreatReportGenerator
from kingsec.application.threat_intelligence.service import ThreatIntelligenceService
from kingsec.domain.identifiers import CveId

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1", tags=["Threat Intelligence"])


def _get_ti_service(request: Request, _: CurrentUser = Depends(get_current_user)) -> ThreatIntelligenceService:
    app = get_application(request)
    return app.resolve(ThreatIntelligenceService)


def _get_report_generator(request: Request, _: CurrentUser = Depends(get_current_user)) -> ThreatReportGenerator:
    app = get_application(request)
    return app.resolve(ThreatReportGenerator)


@router.get("/threat-intelligence/summary")
async def get_summary(
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    summary = await service.get_summary()
    return {
        "total_cves": summary.total_cves,
        "critical_cves": summary.critical_cves,
        "high_cves": summary.high_cves,
        "medium_cves": summary.medium_cves,
        "low_cves": summary.low_cves,
        "kev_count": summary.kev_count,
        "active_exploitations": summary.active_exploitations,
        "average_threat_score": summary.average_threat_score,
        "average_epss_score": summary.average_epss_score,
        "feeds_active": summary.feeds_active,
        "feeds_total": summary.feeds_total,
        "trending_threats": summary.trending_threats,
        "top_critical_cves": summary.top_critical_cves,
        "recent_kev_additions": summary.recent_kev_additions,
    }


@router.get("/cves")
async def list_cves(
    search: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float | None = Query(None),
    max_score: float | None = Query(None),
    is_kev: bool | None = Query(None),
    exploit_maturity: str | None = Query(None),
    published_after: str | None = Query(None),
    published_before: str | None = Query(None),
    vendor: str | None = Query(None),
    product: str | None = Query(None),
    sort_by: str = Query("-threat_score"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    filter_ = CveFilter(
        search=search,
        severity=severity,
        min_score=min_score,
        max_score=max_score,
        is_kev=is_kev,
        exploit_maturity=exploit_maturity,
        published_after=published_after,
        published_before=published_before,
        vendor=vendor,
        product=product,
        sort_by=sort_by,
        page=page,
        page_size=page_size,
    )
    entries, total = await service.get_cves(filter_)
    return {
        "items": [_cve_to_dict(e) for e in entries],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/cves/{cve_id}")
async def get_cve(
    cve_id: str,
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    try:
        cvid = CveId(cve_id)
        entry = await service.get_cve_by_id(cvid)
    except (ValueError, CveNotFoundError):
        entry = await service.get_cve_by_code(cve_id)
    return _cve_to_dict(entry)


@router.post("/cves/{cve_code}/sync")
async def sync_cve(
    cve_code: str,
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    try:
        entry = await service.sync_cve(cve_code)
        return _cve_to_dict(entry)
    except CveNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.delete("/cves/{cve_id}")
async def delete_cve(
    cve_id: str,
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, str]:
    try:
        await service.delete_cve(CveId(cve_id))
        return {"status": "deleted"}
    except CveNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/cves/{cve_id}/risk")
async def get_risk_assessment(
    cve_id: str,
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, float]:
    try:
        risk = await service.get_risk_assessment(CveId(cve_id))
        return {
            "business_risk": risk.business_risk,
            "exploitability_score": risk.exploitability_score,
            "priority_score": risk.priority_score,
            "likelihood": risk.likelihood,
            "overall_threat_score": risk.overall_threat_score,
        }
    except CveNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/kev")
async def list_kev_entries(
    search: str | None = Query(None),
    known_ransomware: bool | None = Query(None),
    vendor: str | None = Query(None),
    product: str | None = Query(None),
    date_added_after: str | None = Query(None),
    due_date_before: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    filter_ = KevFilter(
        search=search,
        known_ransomware=known_ransomware,
        vendor=vendor,
        product=product,
        date_added_after=date_added_after,
        due_date_before=due_date_before,
        page=page,
        page_size=page_size,
    )
    entries, total = await service.get_kev_entries(filter_)
    return {
        "items": [_cve_to_dict(e) for e in entries],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/epss/{cve_code}")
async def get_epss_score(
    cve_code: str,
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    entry = await service.get_cve_by_code(cve_code)
    if entry.epss_data:
        return {
            "score": entry.epss_data.score,
            "percentile": entry.epss_data.percentile,
            "model_version": entry.epss_data.model_version,
            "date": entry.epss_data.date,
        }
    return {"score": 0.0, "percentile": 0.0}


@router.get("/threats/trending")
async def get_trending_threats(
    limit: int = Query(10, ge=1, le=50),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> list[dict[str, Any]]:
    threats = await service.get_trending_threats(limit)
    return [
        {
            "cve_code": t.cve_code,
            "description": t.description,
            "threat_score": t.threat_score,
            "severity": t.severity,
            "is_kev": t.is_kev,
        }
        for t in threats
    ]


@router.get("/threat-intelligence/trends")
async def get_trends(
    days: int = Query(30, ge=7, le=365),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> list[dict[str, Any]]:
    points = await service.get_trend_points(days)
    return [
        {
            "date": p.date,
            "new_cves": p.new_cves,
            "critical_cves": p.critical_cves,
            "kev_additions": p.kev_additions,
            "average_score": p.average_score,
        }
        for p in points
    ]


@router.get("/threat-intelligence/timeline")
async def get_timeline(
    days: int = Query(30, ge=7, le=365),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> list[dict[str, Any]]:
    return await service.get_trending_timeline(days)


@router.get("/threat-intelligence/feeds")
async def list_feeds(
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> list[dict[str, Any]]:
    feeds = await service.get_feeds()
    return [
        {
            "feed_id": f.feed_id,
            "feed_type": f.feed_type.value,
            "title": f.title,
            "description": f.description,
            "source_url": f.source_url,
            "entries": f.entries,
            "last_synced": f.last_synced,
            "status": f.status,
        }
        for f in feeds
    ]


@router.post("/threat-intelligence/feeds")
async def register_feed(
    feed_type: str = Query(...),
    title: str = Query(...),
    source_url: str = Query(""),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> dict[str, Any]:
    feed = await service.register_feed(feed_type, title, source_url)
    return {
        "feed_id": feed.feed_id,
        "feed_type": feed.feed_type.value,
        "title": feed.title,
        "last_synced": feed.last_synced,
    }


@router.get("/threat-intelligence/reports/threat")
async def generate_threat_report(
    days: int = Query(30, ge=7, le=365),
    report_gen: ThreatReportGenerator = Depends(_get_report_generator),
) -> dict[str, Any]:
    return await report_gen.generate_threat_report(days)


@router.get("/threat-intelligence/reports/executive")
async def generate_executive_report(
    days: int = Query(30, ge=7, le=365),
    report_gen: ThreatReportGenerator = Depends(_get_report_generator),
) -> dict[str, Any]:
    return await report_gen.generate_executive_report(days)


@router.get("/threat-intelligence/reports/kev")
async def generate_kev_report(
    report_gen: ThreatReportGenerator = Depends(_get_report_generator),
) -> dict[str, Any]:
    return await report_gen.generate_kev_report()


@router.get("/threat-intelligence/reports/high-risk")
async def generate_high_risk_report(
    min_score: float = Query(50.0),
    report_gen: ThreatReportGenerator = Depends(_get_report_generator),
) -> dict[str, Any]:
    return await report_gen.generate_high_risk_cve_report(min_score)


@router.get("/threat-intelligence/critical")
async def get_critical_cves(
    limit: int = Query(10, ge=1, le=50),
    service: ThreatIntelligenceService = Depends(_get_ti_service),
) -> list[dict[str, Any]]:
    entries = await service.get_critical_cves(limit)
    return [_cve_to_dict(e) for e in entries]


def _cve_to_dict(entry: Any) -> dict[str, Any]:
    cvss = entry.cvss_data
    epss = entry.epss_data
    kev = entry.kev_entry
    return {
        "id": str(entry.id),
        "cve_code": entry.cve_code,
        "description": entry.description,
        "severity": entry.severity,
        "published_date": entry.published_date or "",
        "last_modified": entry.last_modified or "",
        "cvss_data": {
            "version": cvss.version,
            "vector_string": cvss.vector_string,
            "base_score": cvss.base_score,
            "base_severity": cvss.base_severity,
            "exploitability_score": cvss.exploitability_score,
            "impact_score": cvss.impact_score,
            "attack_vector": cvss.attack_vector.value if cvss.attack_vector else "",
            "attack_complexity": cvss.attack_complexity.value if cvss.attack_complexity else "",
            "privileges_required": cvss.privileges_required.value if cvss.privileges_required else "",
            "user_interaction": cvss.user_interaction.value if cvss.user_interaction else "",
            "confidentiality_impact": cvss.confidentiality_impact.value if cvss.confidentiality_impact else "",
            "integrity_impact": cvss.integrity_impact.value if cvss.integrity_impact else "",
            "availability_impact": cvss.availability_impact.value if cvss.availability_impact else "",
        },
        "epss_data": {
            "score": epss.score,
            "percentile": epss.percentile,
            "model_version": epss.model_version,
            "date": epss.date,
        } if epss else None,
        "exploit_maturity": entry.exploit_maturity.value if entry.exploit_maturity else "unknown",
        "affected_products": [
            {
                "vendor": p.vendor,
                "product": p.product,
                "version": p.version,
                "operator": p.operator,
            }
            for p in entry.affected_products
        ],
        "references": [
            {"url": r.url, "source": r.source, "tags": list(r.tags)}
            for r in entry.references
        ],
        "vendor_advisories": list(entry.vendor_advisories),
        "weaknesses": list(entry.weaknesses),
        "is_kev": entry.is_kev,
        "kev_entry": {
            "id": kev.id,
            "cve_id": kev.cve_id,
            "vendor_project": kev.vendor_project,
            "product": kev.product,
            "vulnerability_name": kev.vulnerability_name,
            "date_added": kev.date_added,
            "due_date": kev.due_date,
            "required_action": kev.required_action,
            "known_ransomware_campaign_use": kev.known_ransomware_campaign_use,
            "notes": kev.notes,
        } if kev else None,
        "threat_score": entry.threat_score,
        "exploitability_score": entry.exploitability_score,
        "priority_score": entry.priority_score,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
    }
