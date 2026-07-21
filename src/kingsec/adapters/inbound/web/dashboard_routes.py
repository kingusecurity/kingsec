from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, Query, Request

from kingsec.application.ports.analytics_service import AnalyticsServicePort

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


def _get_service(request: Request) -> AnalyticsServicePort:
    app: Application = get_application(request)
    return cast(AnalyticsServicePort, app.resolve(AnalyticsServicePort))


@router.get("")
async def dashboard_root(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    summary = service.get_summary()
    severity = service.get_severity_breakdown()
    return {
        "summary": {
            "total_scans": summary.total_scans,
            "successful_scans": summary.successful_scans,
            "failed_scans": summary.failed_scans,
            "average_duration_seconds": summary.average_duration_seconds,
            "total_findings": summary.total_findings,
            "critical_findings": summary.critical_findings,
            "high_findings": summary.high_findings,
            "medium_findings": summary.medium_findings,
            "low_findings": summary.low_findings,
            "active_scanners": summary.active_scanners,
            "active_schedules": summary.active_schedules,
            "pending_notifications": summary.pending_notifications,
            "failed_notifications": summary.failed_notifications,
        },
        "severity": {
            "critical": severity.critical,
            "high": severity.high,
            "medium": severity.medium,
            "low": severity.low,
            "info": severity.info,
        },
    }


@router.get("/summary")
async def dashboard_summary(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    s = service.get_summary()
    return {
        "total_scans": s.total_scans,
        "successful_scans": s.successful_scans,
        "failed_scans": s.failed_scans,
        "average_duration_seconds": s.average_duration_seconds,
        "total_findings": s.total_findings,
        "critical_findings": s.critical_findings,
        "high_findings": s.high_findings,
        "medium_findings": s.medium_findings,
        "low_findings": s.low_findings,
        "active_scanners": s.active_scanners,
        "active_schedules": s.active_schedules,
        "pending_notifications": s.pending_notifications,
        "failed_notifications": s.failed_notifications,
    }


@router.get("/severity")
async def severity_breakdown(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    s = service.get_severity_breakdown()
    return {
        "critical": s.critical,
        "high": s.high,
        "medium": s.medium,
        "low": s.low,
        "info": s.info,
    }


@router.get("/trends")
async def trend_data(
    request: Request,
    period: str = Query("weekly", pattern="^(daily|weekly|monthly)$"),
    limit: int = Query(12, ge=1, le=52),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    points = service.get_trend_data(period=period, limit=limit)
    return {"period": period, "points": [{"date": p.date, "value": p.value} for p in points]}


@router.get("/scanners")
async def scanner_statistics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    scanners = service.get_scanner_statistics()
    return {
        "scanners": [
            {
                "scanner_id": s.scanner_id,
                "name": s.name,
                "total_scans": s.total_scans,
                "successful_scans": s.successful_scans,
                "failed_scans": s.failed_scans,
                "average_duration_seconds": s.average_duration_seconds,
            }
            for s in scanners
        ]
    }


@router.get("/workers")
async def worker_statistics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    workers = service.get_worker_statistics()
    return {
        "workers": [
            {
                "worker_id": w.worker_id,
                "status": w.status,
                "uptime_seconds": w.uptime_seconds,
                "jobs_completed": w.jobs_completed,
                "jobs_failed": w.jobs_failed,
                "current_job_id": w.current_job_id,
            }
            for w in workers
        ]
    }


@router.get("/jobs")
async def job_statistics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    j = service.get_job_statistics()
    return {
        "pending": j.pending,
        "running": j.running,
        "completed": j.completed,
        "failed": j.failed,
        "cancelled": j.cancelled,
        "average_duration_seconds": j.average_duration_seconds,
    }


@router.get("/schedules")
async def schedule_statistics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    s = service.get_schedule_statistics()
    return {
        "total": s.total,
        "active": s.active,
        "paused": s.paused,
        "disabled": s.disabled,
    }


@router.get("/notifications")
async def notification_statistics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    n = service.get_notification_statistics()
    return {
        "total": n.total,
        "sent": n.sent,
        "failed": n.failed,
        "pending": n.pending,
        "read": n.read_count,
    }


@router.get("/activity")
async def recent_activity(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    activity = service.get_recent_activity(limit=limit)
    return {"activity": activity}
