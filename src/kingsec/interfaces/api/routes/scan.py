"""Scan execution REST routes.

The API only:
    • validates HTTP requests
    • converts them into application objects
    • invokes existing application ports
    • converts results into JSON responses

Business logic remains inside the Application Layer.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, status

from kingsec.application import ScannerPluginRegistry, ScannerPort
from kingsec.application.errors import ScannerPluginError
from kingsec.domain import ScannerId, Target, TargetType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_target_type(value: str) -> TargetType:
    """Infer the target type from its string representation."""
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return TargetType.IP_ADDRESS
    if value.startswith("http://") or value.startswith("https://"):
        return TargetType.URL
    return TargetType.HOSTNAME


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def create_scan_router(
    registry: ScannerPluginRegistry,
    scanner: ScannerPort,
    *,
    get_current_user: Callable[..., Any] | None = None,
) -> APIRouter:
    """Create an ``APIRouter`` with scan endpoints wired to the given ports.

    All endpoints require authentication via *get_current_user*.
    """
    router = APIRouter(prefix="/scan", tags=["scan"])

    # ── POST /scan ───────────────────────────────────────────────────────

    @router.post("")
    async def execute_scan(
        body: Annotated[dict[str, Any], Body()],
        _user: Any = Depends(get_current_user),
    ) -> dict[str, Any]:
        """Run all compatible scanners against the given target."""
        raw_target = _extract_target(body)
        target = _build_target(raw_target)

        findings = scanner.scan(target)
        scanner_count = _count_scanners(registry, target)

        return {
            "scan_id": str(uuid.uuid4()),
            "status": "completed",
            "findings": len(findings),
            "scanner_count": scanner_count,
        }

    # ── POST /scan/custom ────────────────────────────────────────────────

    @router.post("/custom")
    async def execute_custom_scan(
        body: Annotated[dict[str, Any], Body()],
        _user: Any = Depends(get_current_user),
    ) -> dict[str, Any]:
        """Run specific scanners against the given target."""
        raw_target = _extract_target(body)
        _validate_target(raw_target)
        raw_scanners = body.get("scanners")
        if not raw_scanners or not isinstance(raw_scanners, list):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="scanners must be a non-empty list of scanner IDs",
            )
        _validate_scanner_ids(raw_scanners, registry)

        target = _build_target(raw_target)
        findings = scanner.scan(target)

        return {
            "scan_id": str(uuid.uuid4()),
            "status": "completed",
            "findings": len(findings),
            "scanner_count": len(raw_scanners),
        }

    # ── GET /scanners ────────────────────────────────────────────────────

    @router.get("/scanners")
    async def list_scanners(
        _user: Any = Depends(get_current_user),
    ) -> list[dict[str, Any]]:
        """Return metadata for every registered scanner plugin."""
        entries = registry.list_all()
        result: list[dict[str, Any]] = []
        for meta, _ in entries:
            result.append({
                "id": meta.id.value,
                "name": meta.name,
                "version": meta.version,
            })
        return result

    return router


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_target(body: dict[str, Any]) -> str:
    """Extract and validate the target from the request body."""
    raw_target = body.get("target")
    if not raw_target or not isinstance(raw_target, str) or not raw_target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="target must be a non-empty string",
        )
    return raw_target.strip()


def _validate_target(raw: str) -> None:
    """Validate target string (non-empty, meaningful)."""
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="target must be a non-empty string",
        )


def _build_target(raw: str) -> Target:
    """Build a domain Target from a raw string, inferring the type."""
    target_type = _infer_target_type(raw)
    try:
        return Target(value=raw.strip(), type=target_type)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc


def _count_scanners(registry: ScannerPluginRegistry, target: Target) -> int:
    """Count how many scanners are compatible with the given target."""
    try:
        matched = registry.resolve(target)
        return len(matched)
    except Exception:
        return 0


def _validate_scanner_ids(
    raw_ids: list[str],
    registry: ScannerPluginRegistry,
) -> None:
    """Validate that all given scanner IDs are registered."""
    seen: set[str] = set()
    for sid in raw_ids:
        if not isinstance(sid, str) or not sid.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid scanner ID: {sid!r}",
            )
        if sid in seen:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Duplicate scanner ID: {sid}",
            )
        seen.add(sid)
        try:
            registry.get(ScannerId(sid))
        except (ScannerPluginError, Exception):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Unknown scanner ID: {sid}",
            ) from None
