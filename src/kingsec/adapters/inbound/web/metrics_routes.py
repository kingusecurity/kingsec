"""Performance metrics API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from kingsec.application.ports.outbound.metrics_collector import MetricsCollectorPort
from kingsec.domain import Role

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1", tags=["metrics"])

ADMIN_ONLY = Role.ADMIN


def _get_metrics(request: Request) -> Any:
    app = get_application(request)
    try:
        from kingsec.infrastructure.monitoring.performance_metrics import PerformanceMetrics

        return app.resolve(PerformanceMetrics)
    except Exception:
        return None


def _get_collector(request: Request) -> Any:
    app = get_application(request)
    try:
        return app.resolve(MetricsCollectorPort)
    except Exception:
        return None


@router.get("/metrics/performance")
async def performance_metrics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Get application performance metrics."""
    if user.role != ADMIN_ONLY:
        return {"detail": "Admin access required"}
    metrics = _get_metrics(request)
    if metrics is None:
        return {"status": "unavailable", "detail": "Metrics not initialized"}
    snap = metrics.snapshot()
    return {
        "timestamp": snap.timestamp,
        "uptime_seconds": round(snap.uptime_seconds, 1),
        "request_latency": {
            "count": snap.request_latency.count,
            "avg_ms": round(snap.request_latency.avg_ms, 2),
            "min_ms": round(snap.request_latency.min_ms, 2),
            "max_ms": round(snap.request_latency.max_ms, 2),
            "p95_ms": round(snap.request_latency.p95_ms, 2),
            "p99_ms": round(snap.request_latency.p99_ms, 2),
        },
        "throughput": {
            "requests_per_second": round(snap.throughput.requests_per_second, 2),
            "total_requests": snap.throughput.total_requests,
            "error_count": snap.throughput.error_count,
            "error_rate": round(snap.throughput.error_rate, 4),
        },
        "cache": {
            "hits": snap.cache_stats.hits,
            "misses": snap.cache_stats.misses,
            "hit_ratio": round(snap.cache_stats.hit_ratio, 4),
        },
        "system": {
            "worker_count": snap.worker_count,
            "queue_depth": snap.queue_depth,
            "assessment_count": snap.assessment_count,
            "report_count": snap.report_count,
            "backup_count": snap.backup_count,
        },
    }


@router.get("/metrics/system")
async def system_metrics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Get system resource metrics (CPU, memory, disk)."""
    if user.role != ADMIN_ONLY:
        return {"detail": "Admin access required"}
    collector = _get_collector(request)
    if collector is None:
        return {"status": "unavailable", "detail": "Metrics collector not initialized"}
    try:
        usage = collector.collect_resource_usage()
        return {
            "cpu_percent": usage.cpu_percent,
            "memory_percent": usage.memory_percent,
            "memory_used_mb": round(usage.memory_used_mb, 1),
            "disk_percent": usage.disk_percent,
            "disk_used_gb": round(usage.disk_used_gb, 2),
        }
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


@router.get("/metrics/operations")
async def operation_metrics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Get operation-specific metrics (assessments, reports, backups)."""
    if user.role != ADMIN_ONLY:
        return {"detail": "Admin access required"}
    metrics = _get_metrics(request)
    if metrics is None:
        return {"status": "unavailable", "detail": "Metrics not initialized"}
    operations = {}
    for op_name in ["assessment", "report", "backup", "threat_sync", "scan"]:
        stats = metrics.get_operation_stats(op_name)
        if stats.count > 0:
            operations[op_name] = {
                "count": stats.count,
                "avg_ms": round(stats.avg_ms, 2),
                "min_ms": round(stats.min_ms, 2),
                "max_ms": round(stats.max_ms, 2),
                "p95_ms": round(stats.p95_ms, 2),
            }
    return {"operations": operations}
