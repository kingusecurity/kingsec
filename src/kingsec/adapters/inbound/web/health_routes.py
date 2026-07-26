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
