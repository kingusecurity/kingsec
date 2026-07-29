from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from kingsec.application.errors import AlertNotFoundError, MonitorEventNotFoundError, RuleNotFoundError
from kingsec.application.monitoring.ports import AlertFilter, MonitorEventFilter, MonitoringSummaryStats, RuleFilter
from kingsec.application.monitoring.service import MonitoringService
from kingsec.domain.monitoring import (
    Alert,
    AlertSeverity,
    AlertStatus,
    MonitorEvent,
    MonitorEventType,
    MonitoringDashboardSummary,
    MonitoringStatus,
    Rule,
)

from .auth import CurrentUser, get_current_user, require_analyst
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["monitoring"])


def _get_service(request: Request) -> MonitoringService:
    app: Application = get_application(request)
    svc = app.resolve(MonitoringService)
    if svc is None:
        raise HTTPException(status_code=500, detail="MonitoringService not available")
    return cast(MonitoringService, svc)


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "id": str(rule.id),
        "name": rule.name,
        "description": rule.description,
        "event_type": rule.event_type.value if rule.event_type else None,
        "conditions": [{"field": c.field, "operator": c.operator.value, "value": c.value} for c in rule.conditions],
        "alert_severity": rule.alert_severity.value,
        "alert_title_template": rule.alert_title_template,
        "alert_description_template": rule.alert_description_template,
        "enabled": rule.enabled,
        "cooldown_minutes": rule.cooldown_minutes,
        "notify_channels": list(rule.notify_channels),
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


def _event_to_dict(event: MonitorEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "event_type": event.event_type.value,
        "asset_id": event.asset_id,
        "assessment_id": event.assessment_id,
        "source": event.source,
        "title": event.title,
        "description": event.description,
        "severity": event.severity.value,
        "context": [{"key": c.key, "value": c.value, "previous_value": c.previous_value} for c in event.context],
        "timestamp": event.timestamp,
    }


def _alert_to_dict(alert: Alert) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "rule_id": alert.rule_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "source_event_id": alert.source_event_id,
        "asset_id": alert.asset_id,
        "assessment_id": alert.assessment_id,
        "created_at": alert.created_at,
        "acknowledged_at": alert.acknowledged_at,
        "resolved_at": alert.resolved_at,
        "acknowledged_by": alert.acknowledged_by,
        "resolved_by": alert.resolved_by,
    }


# =====================================================================
#  Summary & Dashboard
# =====================================================================


@router.get("/monitoring/summary")
def get_monitoring_summary(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> MonitoringDashboardSummary:
    from kingsec.application.monitoring.dashboard import MonitoringDashboardService
    app: Application = get_application(request)
    svc = app.resolve(MonitoringDashboardService)
    if svc is None:
        raise HTTPException(status_code=500, detail="MonitoringDashboardService not available")
    return cast(MonitoringDashboardService, svc).get_summary()


@router.get("/monitoring/stats")
def get_monitoring_stats(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> MonitoringSummaryStats:
    from kingsec.application.monitoring.dashboard import MonitoringDashboardService
    app: Application = get_application(request)
    svc = app.resolve(MonitoringDashboardService)
    if svc is None:
        raise HTTPException(status_code=500, detail="MonitoringDashboardService not available")
    return cast(MonitoringDashboardService, svc).get_summary_stats()


@router.get("/monitoring/health")
def get_monitoring_health(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    from kingsec.application.monitoring.dashboard import MonitoringDashboardService
    app: Application = get_application(request)
    svc = app.resolve(MonitoringDashboardService)
    if svc is None:
        raise HTTPException(status_code=500, detail="MonitoringDashboardService not available")
    status = cast(MonitoringDashboardService, svc).get_health_status()
    return {"status": status.value}


# =====================================================================
#  Events
# =====================================================================


@router.get("/monitoring/events")
def list_monitoring_events(
    request: Request,
    event_type: str | None = None,
    asset_id: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    filter_ = MonitorEventFilter(
        event_type=MonitorEventType(event_type) if event_type else None,
        asset_id=asset_id,
        severity=AlertSeverity(severity) if severity else None,
        source=source,
        search=search,
    )
    svc = _get_service(request)
    items = svc.list_events(filter_, limit=limit, offset=offset)
    total = svc.count_events(filter_)
    return {"items": [_event_to_dict(e) for e in items], "total": total, "limit": limit, "offset": offset}


@router.get("/monitoring/events/{event_id}")
def get_monitoring_event(
    event_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _event_to_dict(_get_service(request).get_event(event_id))
    except MonitorEventNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  Alerts
# =====================================================================


@router.get("/monitoring/alerts")
def list_alerts(
    request: Request,
    rule_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    asset_id: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    filter_ = AlertFilter(
        rule_id=rule_id,
        severity=AlertSeverity(severity) if severity else None,
        status=AlertStatus(status) if status else None,
        asset_id=asset_id,
        search=search,
    )
    svc = _get_service(request)
    items = svc.list_alerts(filter_, limit=limit, offset=offset)
    total = svc.count_alerts(filter_)
    return {"items": [_alert_to_dict(a) for a in items], "total": total, "limit": limit, "offset": offset}


@router.get("/monitoring/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _alert_to_dict(_get_service(request).get_alert(alert_id))
    except AlertNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _alert_to_dict(_get_service(request).acknowledge_alert(alert_id))
    except AlertNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _alert_to_dict(_get_service(request).resolve_alert(alert_id))
    except AlertNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/alerts/{alert_id}/dismiss")
def dismiss_alert(
    alert_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _alert_to_dict(_get_service(request).dismiss_alert(alert_id))
    except AlertNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  Rules
# =====================================================================


@router.get("/monitoring/rules")
def list_rules(
    request: Request,
    enabled: bool | None = None,
    event_type: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    filter_ = RuleFilter(
        enabled=enabled,
        event_type=MonitorEventType(event_type) if event_type else None,
        search=search,
    )
    svc = _get_service(request)
    items = svc.list_rules(filter_, limit=limit, offset=offset)
    total = svc.count_rules(filter_)
    return {"items": [_rule_to_dict(r) for r in items], "total": total, "limit": limit, "offset": offset}


@router.get("/monitoring/rules/{rule_id}")
def get_rule(
    rule_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _rule_to_dict(_get_service(request).get_rule(rule_id))
    except RuleNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/rules")
def create_rule(
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    rule = _get_service(request).create_rule(
        name=body["name"],
        event_type_str=body.get("event_type"),
        conditions=body.get("conditions"),
        alert_severity=body.get("alert_severity", "medium"),
        alert_title_template=body.get("alert_title_template", ""),
        alert_description_template=body.get("alert_description_template", ""),
        cooldown_minutes=body.get("cooldown_minutes", 60),
        notify_channels=body.get("notify_channels"),
    )
    return _rule_to_dict(rule)


@router.put("/monitoring/rules/{rule_id}")
def update_rule(
    rule_id: str,
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        rule = _get_service(request).update_rule(rule_id, body)
        return _rule_to_dict(rule)
    except RuleNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/monitoring/rules/{rule_id}")
def delete_rule(
    rule_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, str]:
    try:
        _get_service(request).delete_rule(rule_id)
        return {"status": "deleted"}
    except RuleNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/rules/{rule_id}/enable")
def enable_rule(
    rule_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _rule_to_dict(_get_service(request).enable_rule(rule_id))
    except RuleNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/rules/{rule_id}/disable")
def disable_rule(
    rule_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _rule_to_dict(_get_service(request).disable_rule(rule_id))
    except RuleNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/monitoring/rules/seed")
def seed_default_rules(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    rules = _get_service(request).seed_default_rules()
    return [_rule_to_dict(r) for r in rules]


# =====================================================================
#  Trends
# =====================================================================


@router.get("/monitoring/trends")
def get_monitoring_trends(
    request: Request,
    days: int = 30,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    from kingsec.application.monitoring.dashboard import MonitoringDashboardService
    app: Application = get_application(request)
    ds = app.resolve(MonitoringDashboardService)
    if ds is None:
        raise HTTPException(status_code=500, detail="MonitoringDashboardService not available")
    ds = cast(MonitoringDashboardService, ds)
    return {
        "events": [{"date": t.date, "count": t.events_count} for t in ds.get_event_trend(days=days)],
        "alerts": [{"date": t.date, "count": t.alerts_count, "critical": t.critical_alerts, "high": t.high_alerts} for t in ds.get_alert_trend(days=days)],
        "exposures": ds.get_exposure_trend(days=days),
        "compliance": ds.get_compliance_trend(days=days),
        "risk": ds.get_risk_trend(days=days),
    }
