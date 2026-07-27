"""Scanner discovery REST routes — read-only health and status.

These endpoints report which scanners are installed, their versions,
required assets, and overall readiness. They never install or modify
anything on the system.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path

from kingsec.application.scanner_discovery import ScannerDiscoveryService

# Reuse the same discovery instance across requests (stateless + thread-safe).
_discovery = ScannerDiscoveryService()


def create_scanner_discovery_router(
    *,
    get_current_user: Callable[..., Any] | None = None,
) -> APIRouter:
    """Create an ``APIRouter`` with scanner discovery endpoints.

    All endpoints are read-only and require authentication.
    """
    router = APIRouter(prefix="/scanners", tags=["scanners"])

    # ── GET /scanners ─────────────────────────────────────────────────────

    @router.get("")
    async def list_scanners(
        _user: Any = Depends(get_current_user),
    ) -> list[dict[str, Any]]:
        """Return discovery status for every known scanner."""
        statuses = _discovery.get_all_statuses()
        return [_status_to_dict(s) for s in statuses]

    # ── GET /scanners/health ──────────────────────────────────────────────

    @router.get("/health")
    async def scanner_health(
        _user: Any = Depends(get_current_user),
    ) -> dict[str, Any]:
        """Return an aggregate health report across all scanners."""
        report = _discovery.get_health_report()
        return {
            "total": report.total,
            "installed": report.installed,
            "usable": report.usable,
            "partial": report.partial,
            "missing": report.missing,
            "health_score": report.health_score,
            "scanners": [_status_to_dict(s) for s in report.scanners],
        }

    # ── GET /scanners/{scanner_id} ───────────────────────────────────────

    @router.get("/{scanner_id}")
    async def get_scanner_detail(
        scanner_id: Annotated[
            str,
            Path(
                description="Scanner identifier (e.g. nmap, nuclei, trivy)",
                pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
            ),
        ],
        _user: Any = Depends(get_current_user),
    ) -> dict[str, Any]:
        """Return discovery status for a single scanner."""
        s = _discovery.get_scanner_status(scanner_id)
        if not s.installed and s.availability_reason and "Unknown" in s.availability_reason:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown scanner: {scanner_id!r}",
            )
        return _status_to_dict(s)

    return router


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _status_to_dict(st: Any) -> dict[str, Any]:
    """Convert a ``ScannerStatus`` to a JSON-serialisable dict."""
    return {
        "scanner_id": st.scanner_id,
        "name": st.name,
        "installed": st.installed,
        "executable_path": st.executable_path,
        "version": st.version,
        "usable": st.usable,
        "availability_reason": st.availability_reason,
        "warnings": list(st.warnings),
        "required_assets": list(st.required_assets),
        "missing_assets": list(st.missing_assets),
        "install_hints": list(st.install_hints),
    }
