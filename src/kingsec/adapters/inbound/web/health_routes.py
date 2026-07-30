from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, Request

from kingsec.application.ports.production_service import ProductionServicePort
from kingsec.domain import Role
from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    LivenessReport,
    ReadinessReport,
    StartupCheck,
    SystemMetrics,
)

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

from .auth import require_role
from .dependencies import get_application

router = APIRouter(prefix="/api/v1", tags=["health"])


def _get_service(request: Request) -> ProductionServicePort:
    app: Application = get_application(request)
    return cast(ProductionServicePort, app.resolve(ProductionServicePort))


@router.get("/healthz/live", response_model=LivenessReport)
def liveness(request: Request) -> LivenessReport:
    return _get_service(request).get_liveness()


@router.get("/healthz/ready", response_model=ReadinessReport)
def readiness(request: Request) -> ReadinessReport:
    return _get_service(request).get_readiness()


@router.get("/healthz/health", response_model=HealthCheck, dependencies=[Depends(require_role(Role.ADMIN))])
def health(request: Request) -> HealthCheck:
    return _get_service(request).get_health()


@router.get("/healthz/metrics", response_model=SystemMetrics, dependencies=[Depends(require_role(Role.ADMIN))])
def metrics(request: Request) -> SystemMetrics:
    return _get_service(request).collect_metrics()


@router.get("/healthz/startup", response_model=list[StartupCheck], dependencies=[Depends(require_role(Role.ADMIN))])
def startup(request: Request) -> list[StartupCheck]:
    return _get_service(request).validate_startup()


@router.get(
    "/healthz/configuration", response_model=list[StartupCheck], dependencies=[Depends(require_role(Role.ADMIN))]
)
def configuration(request: Request) -> list[StartupCheck]:
    return _get_service(request).validate_configuration()


@router.get(
    "/healthz/dependencies", response_model=list[DependencyHealth], dependencies=[Depends(require_role(Role.ADMIN))]
)
def dependencies(request: Request) -> list[DependencyHealth]:
    return _get_service(request).list_dependencies()


@router.get("/healthz/resources", response_model=SystemMetrics, dependencies=[Depends(require_role(Role.ADMIN))])
def resources(request: Request) -> SystemMetrics:
    return _get_service(request).get_system_resources()


@router.post("/healthz/shutdown", dependencies=[Depends(require_role(Role.ADMIN))])
def shutdown(request: Request) -> dict[str, Any]:
    _get_service(request).shutdown()
    return {"status": "shutdown_initiated"}


@router.post("/healthz/restart", dependencies=[Depends(require_role(Role.ADMIN))])
def restart(request: Request) -> dict[str, Any]:
    _get_service(request).restart()
    return {"status": "restart_initiated"}


@router.get("/health")
def health_simple() -> dict[str, Any]:
    """Simple liveness endpoint (no auth, no dependency checks)."""
    return {"status": "healthy"}


@router.get(
    "/healthz/performance", response_model=SystemMetrics, dependencies=[Depends(require_role(Role.ADMIN))]
)
def performance_health(request: Request) -> dict[str, Any]:
    """Performance-specific health check with cache and metrics info."""
    service = _get_service(request)
    metrics_data = service.collect_metrics()
    result: dict[str, Any] = {
        "status": "healthy",
        "cpu_percent": metrics_data.cpu_percent,
        "memory_percent": metrics_data.memory_percent,
        "disk_percent": metrics_data.disk_percent,
        "uptime_seconds": metrics_data.uptime_seconds,
    }
    try:
        from kingsec.infrastructure.cache.memory_cache import MemoryCacheService

        app: Application = get_application(request)
        cache = app.resolve(MemoryCacheService)
        result["cache"] = {
            "size": cache.size,
            "hit_ratio": round(cache.hit_ratio, 4),
            "hits": cache.hits,
            "misses": cache.misses,
        }
    except Exception:
        result["cache"] = {"status": "unavailable"}
    return result
