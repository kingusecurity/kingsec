"""Performance metrics API endpoints."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, Request

from kingsec.application.ports.outbound.metrics_collector import MetricsCollectorPort
from kingsec.domain import Role

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1", tags=["metrics"])

ADMIN_ONLY = Role.ADMIN

# KSEC-88-04: structlog directly, matching error_handlers.py/auth.py's
# established pattern - see error_handlers.py's own comment for why
# (adapters/infrastructure are sibling layers under the import-linter
# "Hexagonal layering" contract and must not import each other).
_logger = structlog.get_logger("kingsec.adapters.inbound.web.metrics_routes")


def _get_metrics(request: Request) -> Any:
    app = get_application(request)
    try:
        from kingsec.application.ports.outbound.performance_metrics import PerformanceMetricsPort

        return app.resolve(PerformanceMetricsPort)
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
        # KSEC-88-04: was `collect_resource_usage()`, a method
        # MetricsCollectorPort never declared and no concrete
        # implementation (ProcessMetricsCollector/ResourceMonitor) ever
        # defined - every real invocation of this endpoint raised
        # AttributeError unconditionally. collect_all() is the port
        # method that returns exactly the ResourceUsage fields already
        # destructured below. Found while auditing this except block for
        # KSEC-88-04; fixed as the smallest correct change since it's the
        # single call this handler exists to guard.
        usage = collector.collect_all()
        return {
            "cpu_percent": usage.cpu_percent,
            "memory_percent": usage.memory_percent,
            "memory_used_mb": round(usage.memory_used_mb, 1),
            "disk_percent": usage.disk_percent,
            "disk_used_gb": round(usage.disk_used_gb, 2),
        }
    except Exception:
        # KSEC-88-04: collect_resource_usage() wraps OS-level resource
        # queries (e.g. psutil) whose failure messages can contain
        # filesystem paths or other host details - str(exc) was returned
        # to any authenticated admin verbatim. Logged server-side only,
        # same generic-message convention as admin_operation_error().
        _logger.exception("failed to collect system resource metrics")
        return {"status": "error", "detail": "Failed to collect system metrics"}


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
