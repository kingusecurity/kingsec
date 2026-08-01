from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from kingsec.application.errors import AlertNotFoundError, MonitorEventNotFoundError, RuleNotFoundError
from kingsec.application.monitoring.ports import (
    AlertFilter,
    AlertRepositoryPort,
    AssetHealthSnapshot,
    MonitorEventFilter,
    MonitoringDashboardRepositoryPort,
    MonitoringEventRepositoryPort,
    MonitoringSummaryStats,
    MonitoringTrendPoint,
    RuleFilter,
    RuleRepositoryPort,
)
from kingsec.domain.monitoring import (
    Alert,
    MonitorEvent,
    MonitoringDashboardSummary,
    MonitoringStatus,
    Rule,
)
from kingsec.infrastructure.persistence.mappers import (
    alert_to_domain,
    alert_to_orm,
    monitor_event_to_domain,
    monitor_event_to_orm,
    rule_to_domain,
    rule_to_orm,
)
from kingsec.infrastructure.persistence.models import (
    AlertModel,
    AssetModel,
    ExposureModel,
    MonitorEventModel,
    RuleModel,
)


class SQLAlchemyMonitoringEventRepository(MonitoringEventRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_event(self, event: MonitorEvent) -> None:
        orm = monitor_event_to_orm(event)
        self._session.add(orm)
        self._session.commit()

    def get_event(self, event_id: str) -> MonitorEvent:
        orm = self._session.get(MonitorEventModel, event_id)
        if orm is None:
            raise MonitorEventNotFoundError(f"Monitor event not found: {event_id}")
        return monitor_event_to_domain(orm)

    def fetch_events(
        self,
        filter_: MonitorEventFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MonitorEvent]:
        query = select(MonitorEventModel)
        query = _apply_event_filter(query, filter_)
        query = query.order_by(MonitorEventModel.timestamp.desc()).offset(offset).limit(limit)
        orms = self._session.execute(query).scalars().all()
        return [monitor_event_to_domain(o) for o in orms]

    def count_events(self, filter_: MonitorEventFilter | None = None) -> int:
        query = select(func.count(MonitorEventModel.id))
        query = _apply_event_filter(query, filter_)
        result = self._session.execute(query).scalar()
        return result or 0

    def get_event_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        stmt = select(MonitorEventModel.severity, MonitorEventModel.timestamp).where(MonitorEventModel.timestamp >= cutoff)
        rows = self._session.execute(stmt).all()
        daily: dict[str, dict[str, int]] = {}
        for severity, ts in rows:
            day = ts[:10]
            if day not in daily:
                daily[day] = {}
            daily[day][severity] = daily[day].get(severity, 0) + 1
        return [
            MonitoringTrendPoint(
                date=day,
                events_count=sum(d.values()),
                alerts_count=0,
                critical_alerts=d.get("critical", 0),
                high_alerts=d.get("high", 0),
            )
            for day, d in sorted(daily.items())
        ]


class SQLAlchemyAlertRepository(AlertRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_alert(self, alert: Alert) -> None:
        existing = self._session.get(AlertModel, str(alert.id))
        if existing:
            _update_alert_orm(existing, alert)
        else:
            orm = alert_to_orm(alert)
            self._session.add(orm)
        self._session.commit()

    def get_alert(self, alert_id: str) -> Alert:
        orm = self._session.get(AlertModel, alert_id)
        if orm is None:
            raise AlertNotFoundError(f"Alert not found: {alert_id}")
        return alert_to_domain(orm)

    def fetch_alerts(
        self,
        filter_: AlertFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        query = select(AlertModel)
        query = _apply_alert_filter(query, filter_)
        query = query.order_by(AlertModel.created_at.desc()).offset(offset).limit(limit)
        orms = self._session.execute(query).scalars().all()
        return [alert_to_domain(o) for o in orms]

    def count_alerts(self, filter_: AlertFilter | None = None) -> int:
        query = select(func.count(AlertModel.id))
        query = _apply_alert_filter(query, filter_)
        result = self._session.execute(query).scalar()
        return result or 0

    def get_open_alerts_count(self) -> int:
        stmt = select(func.count(AlertModel.id)).where(AlertModel.status == "open")
        return self._session.execute(stmt).scalar() or 0

    def get_critical_alerts_count(self) -> int:
        stmt = select(func.count(AlertModel.id)).where(
            AlertModel.severity == "critical", AlertModel.status == "open"
        )
        return self._session.execute(stmt).scalar() or 0

    def get_alert_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        stmt = select(AlertModel.severity, AlertModel.created_at).where(AlertModel.created_at >= cutoff)
        rows = self._session.execute(stmt).all()
        daily: dict[str, dict[str, int]] = {}
        for severity, ts in rows:
            day = ts[:10]
            if day not in daily:
                daily[day] = {}
            daily[day][severity] = daily[day].get(severity, 0) + 1
        return [
            MonitoringTrendPoint(
                date=day,
                events_count=0,
                alerts_count=sum(d.values()),
                critical_alerts=d.get("critical", 0),
                high_alerts=d.get("high", 0),
            )
            for day, d in sorted(daily.items())
        ]


class SQLAlchemyRuleRepository(RuleRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_rule(self, rule: Rule) -> None:
        existing = self._session.get(RuleModel, str(rule.id))
        if existing:
            _update_rule_orm(existing, rule)
        else:
            orm = rule_to_orm(rule)
            self._session.add(orm)
        self._session.commit()

    def get_rule(self, rule_id: str) -> Rule:
        orm = self._session.get(RuleModel, rule_id)
        if orm is None:
            raise RuleNotFoundError(f"Rule not found: {rule_id}")
        return rule_to_domain(orm)

    def delete_rule(self, rule_id: str) -> None:
        orm = self._session.get(RuleModel, rule_id)
        if orm:
            self._session.delete(orm)
            self._session.commit()

    def fetch_rules(
        self,
        filter_: RuleFilter | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Rule]:
        query = select(RuleModel)
        query = _apply_rule_filter(query, filter_)
        query = query.order_by(RuleModel.created_at.desc()).offset(offset).limit(limit)
        orms = self._session.execute(query).scalars().all()
        return [rule_to_domain(o) for o in orms]

    def count_rules(self, filter_: RuleFilter | None = None) -> int:
        query = select(func.count(RuleModel.id))
        query = _apply_rule_filter(query, filter_)
        result = self._session.execute(query).scalar()
        return result or 0

    def get_enabled_rules(self) -> list[Rule]:
        orms = self._session.execute(
            select(RuleModel).where(RuleModel.enabled == True)  # noqa: E712
        ).scalars().all()
        return [rule_to_domain(o) for o in orms]


class SQLAlchemyMonitoringDashboardRepository(MonitoringDashboardRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_dashboard_summary(self) -> MonitoringDashboardSummary:
        now = datetime.now(UTC)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        (now - timedelta(days=7)).isoformat()

        events_24h = self._session.execute(
            select(func.count(MonitorEventModel.id)).where(MonitorEventModel.timestamp >= cutoff_24h)
        ).scalar() or 0

        open_alerts = self._session.execute(
            select(func.count(AlertModel.id)).where(AlertModel.status == "open")
        ).scalar() or 0

        critical_alerts = self._session.execute(
            select(func.count(AlertModel.id)).where(
                AlertModel.severity == "critical", AlertModel.status == "open"
            )
        ).scalar() or 0

        high_alerts = self._session.execute(
            select(func.count(AlertModel.id)).where(
                AlertModel.severity == "high", AlertModel.status == "open"
            )
        ).scalar() or 0

        active_rules = self._session.execute(
            select(func.count(RuleModel.id)).where(RuleModel.enabled == True)  # noqa: E712
        ).scalar() or 0

        total_assets = self._session.execute(
            select(func.count(AssetModel.id))
        ).scalar() or 0

        asset_health = 100.0
        if total_assets > 0:
            critical_assets = self._session.execute(
                select(func.count(AssetModel.id)).where(AssetModel.risk_score >= 75)
            ).scalar() or 0
            asset_health = max(0.0, 100.0 - (critical_assets / total_assets * 100.0))

        cert_expiring = self._session.execute(
            select(func.count(ExposureModel.id)).where(
                ExposureModel.exposure_type == "expired_certificate",
                ExposureModel.status == "active",
            )
        ).scalar() or 0

        recent_events = []
        event_orms = self._session.execute(
            select(MonitorEventModel).order_by(MonitorEventModel.timestamp.desc()).limit(5)
        ).scalars().all()
        for evt_orm in event_orms:
            recent_events.append({
                "id": evt_orm.id,
                "event_type": evt_orm.event_type,
                "title": evt_orm.title,
                "timestamp": evt_orm.timestamp,
            })

        alert_orms = self._session.execute(
            select(AlertModel).where(AlertModel.status == "open").order_by(AlertModel.created_at.desc()).limit(5)
        ).scalars().all()
        recent_alerts_list = []
        for alrt_orm in alert_orms:
            recent_alerts_list.append({
                "id": alrt_orm.id,
                "title": alrt_orm.title,
                "severity": alrt_orm.severity,
                "created_at": alrt_orm.created_at,
            })

        return MonitoringDashboardSummary(
            total_events_24h=events_24h,
            total_alerts_open=open_alerts,
            total_alerts_critical=critical_alerts,
            total_alerts_high=high_alerts,
            total_rules_active=active_rules,
            asset_health_percentage=round(asset_health, 1),
            last_scan_time=cutoff_24h,
            upcoming_certificate_expirations=cert_expiring,
            assets_monitored=total_assets,
            recent_events=recent_events,
            recent_alerts=recent_alerts_list,
        )

    def get_asset_health_snapshots(self) -> list[AssetHealthSnapshot]:
        orms = self._session.execute(
            select(AssetModel).limit(100)
        ).scalars().all()
        result: list[AssetHealthSnapshot] = []
        for o in orms:
            if o.risk_score >= 75:
                status = MonitoringStatus.CRITICAL
            elif o.risk_score >= 50:
                status = MonitoringStatus.WARNING
            else:
                status = MonitoringStatus.HEALTHY

            exposure_count = self._session.execute(
                select(func.count(ExposureModel.id)).where(
                    ExposureModel.asset_id == o.id, ExposureModel.status == "active"
                )
            ).scalar() or 0

            result.append(
                AssetHealthSnapshot(
                    asset_id=o.id,
                    status=status,
                    risk_score=o.risk_score,
                    exposure_count=exposure_count,
                    finding_count=len(o.findings or []),
                    last_seen=o.last_seen,
                )
            )
        return result

    def get_summary_stats(self) -> MonitoringSummaryStats:
        now = datetime.now(UTC)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        cutoff_7d = (now - timedelta(days=7)).isoformat()

        events_24h = self._session.execute(
            select(func.count(MonitorEventModel.id)).where(MonitorEventModel.timestamp >= cutoff_24h)
        ).scalar() or 0
        events_7d = self._session.execute(
            select(func.count(MonitorEventModel.id)).where(MonitorEventModel.timestamp >= cutoff_7d)
        ).scalar() or 0

        alerts_24h = self._session.execute(
            select(func.count(AlertModel.id)).where(AlertModel.created_at >= cutoff_24h)
        ).scalar() or 0

        open_alerts = self._session.execute(
            select(func.count(AlertModel.id)).where(AlertModel.status == "open")
        ).scalar() or 0

        critical_alerts = self._session.execute(
            select(func.count(AlertModel.id)).where(
                AlertModel.severity == "critical", AlertModel.status == "open"
            )
        ).scalar() or 0

        high_alerts = self._session.execute(
            select(func.count(AlertModel.id)).where(
                AlertModel.severity == "high", AlertModel.status == "open"
            )
        ).scalar() or 0

        active_rules = self._session.execute(
            select(func.count(RuleModel.id)).where(RuleModel.enabled == True)  # noqa: E712
        ).scalar() or 0
        total_rules = self._session.execute(
            select(func.count(RuleModel.id))
        ).scalar() or 0

        total_assets = self._session.execute(
            select(func.count(AssetModel.id))
        ).scalar() or 0

        healthy = warning = ccritical = 0
        for o in self._session.execute(select(AssetModel.risk_score)).all():
            if o[0] >= 75:
                ccritical += 1
            elif o[0] >= 50:
                warning += 1
            else:
                healthy += 1

        return MonitoringSummaryStats(
            events_last_24h=events_24h,
            events_last_7d=events_7d,
            alerts_last_24h=alerts_24h,
            alerts_open=open_alerts,
            alerts_critical=critical_alerts,
            alerts_high=high_alerts,
            rules_active=active_rules,
            rules_total=total_rules,
            assets_monitored=total_assets,
            assets_healthy=healthy,
            assets_warning=warning,
            assets_critical=ccritical,
            total_changes_detected=events_24h,
        )

    def get_exposure_trend(self, days: int = 30) -> list[dict[str, Any]]:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        stmt = select(ExposureModel.severity, ExposureModel.created_at).where(ExposureModel.created_at >= cutoff)
        rows = self._session.execute(stmt).all()
        daily: dict[str, dict[str, int]] = {}
        for severity, ts in rows:
            day = ts[:10]
            if day not in daily:
                daily[day] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            daily[day][severity] = daily[day].get(severity, 0) + 1
        return [
            {"date": day, **counts, "total": sum(counts.values())}
            for day, counts in sorted(daily.items())
        ]

    def get_compliance_trend(self, days: int = 30) -> list[dict[str, Any]]:
        return [{"date": (datetime.now(UTC) - timedelta(days=i)).strftime("%Y-%m-%d"), "score": 100.0} for i in range(days, 0, -1)]

    def get_risk_trend(self, days: int = 30) -> list[dict[str, Any]]:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        stmt = select(AssetModel.risk_score, AssetModel.updated_at).where(
            AssetModel.updated_at >= cutoff
        )
        rows = self._session.execute(stmt).all()
        daily: dict[str, list[float]] = {}
        for score, ts in rows:
            day = (ts or "")[:10] if ts else ""
            if day:
                if day not in daily:
                    daily[day] = []
                daily[day].append(score)
        return [
            {"date": day, "average_risk": round(sum(scores) / len(scores), 2) if scores else 0, "max_risk": max(scores) if scores else 0}
            for day, scores in sorted(daily.items())
        ]


def _update_alert_orm(orm: AlertModel, alert: Alert) -> None:
    import json
    orm.rule_id = alert.rule_id
    orm.title = alert.title
    orm.description = alert.description
    orm.severity = alert.severity.value
    orm.status = alert.status.value
    orm.source_event_id = alert.source_event_id
    orm.asset_id = alert.asset_id
    orm.assessment_id = alert.assessment_id
    orm.metadata_json = json.dumps(alert.metadata) if alert.metadata else None
    orm.acknowledged_at = alert.acknowledged_at
    orm.resolved_at = alert.resolved_at
    orm.acknowledged_by = alert.acknowledged_by
    orm.resolved_by = alert.resolved_by


def _update_rule_orm(orm: RuleModel, rule: Rule) -> None:
    import json
    orm.name = rule.name
    orm.description = rule.description
    orm.event_type = rule.event_type.value if rule.event_type else None
    orm.conditions_json = json.dumps([{"field": c.field, "operator": c.operator.value, "value": c.value} for c in rule.conditions]) if rule.conditions else None
    orm.alert_severity = rule.alert_severity.value
    orm.alert_title_template = rule.alert_title_template
    orm.alert_description_template = rule.alert_description_template
    orm.enabled = rule.enabled
    orm.cooldown_minutes = rule.cooldown_minutes
    orm.notify_channels_json = json.dumps(list(rule.notify_channels)) if rule.notify_channels else None
    orm.metadata_json = json.dumps(rule.metadata) if rule.metadata else None
    orm.updated_at = datetime.now(UTC).isoformat()


def _apply_event_filter(query: Select[Any], filter_: MonitorEventFilter | None) -> Select[Any]:
    if filter_ is None:
        return query
    q = query
    if filter_.event_type:
        q = q.where(MonitorEventModel.event_type == filter_.event_type.value)
    if filter_.asset_id:
        q = q.where(MonitorEventModel.asset_id == filter_.asset_id)
    if filter_.severity:
        q = q.where(MonitorEventModel.severity == filter_.severity.value)
    if filter_.source:
        q = q.where(MonitorEventModel.source == filter_.source)
    if filter_.search:
        pattern = f"%{filter_.search}%"
        q = q.where(or_(MonitorEventModel.title.ilike(pattern), MonitorEventModel.description.ilike(pattern)))
    if filter_.created_after:
        q = q.where(MonitorEventModel.timestamp >= filter_.created_after)
    if filter_.created_before:
        q = q.where(MonitorEventModel.timestamp <= filter_.created_before)
    return q


def _apply_alert_filter(query: Select[Any], filter_: AlertFilter | None) -> Select[Any]:
    if filter_ is None:
        return query
    q = query
    if filter_.rule_id:
        q = q.where(AlertModel.rule_id == filter_.rule_id)
    if filter_.severity:
        q = q.where(AlertModel.severity == filter_.severity.value)
    if filter_.status:
        q = q.where(AlertModel.status == filter_.status.value)
    if filter_.asset_id:
        q = q.where(AlertModel.asset_id == filter_.asset_id)
    if filter_.search:
        pattern = f"%{filter_.search}%"
        q = q.where(or_(AlertModel.title.ilike(pattern), AlertModel.description.ilike(pattern)))
    if filter_.created_after:
        q = q.where(AlertModel.created_at >= filter_.created_after)
    if filter_.created_before:
        q = q.where(AlertModel.created_at <= filter_.created_before)
    return q


def _apply_rule_filter(query: Select[Any], filter_: RuleFilter | None) -> Select[Any]:
    if filter_ is None:
        return query
    q = query
    if filter_.enabled is not None:
        q = q.where(RuleModel.enabled == filter_.enabled)
    if filter_.event_type:
        q = q.where(RuleModel.event_type == filter_.event_type.value)
    if filter_.search:
        pattern = f"%{filter_.search}%"
        q = q.where(or_(RuleModel.name.ilike(pattern), RuleModel.description.ilike(pattern)))
    return q
