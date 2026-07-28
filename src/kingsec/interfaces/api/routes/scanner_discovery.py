"""Scanner discovery REST routes — read-only health and status.

These endpoints report which scanners are installed, their versions,
required assets, and overall readiness. They never install or modify
anything on the system.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import PlainTextResponse

from kingsec.application.scanner_discovery import ScannerDiscoveryService
from kingsec.application.scanner_installer import ScannerInstaller

# Reuse the same discovery instance across requests (stateless + thread-safe).
_discovery = ScannerDiscoveryService()
_installer = ScannerInstaller()


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

    # ── GET /scanners/{scanner_id}/diagnostics ───────────────────────────

    @router.get("/{scanner_id}/diagnostics")
    async def get_scanner_diagnostics(
        scanner_id: Annotated[
            str,
            Path(
                description="Scanner identifier (e.g. nmap, nuclei, trivy)",
                pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
            ),
        ],
        fmt: str = Query("json", description="Output format: json, markdown, text"),
        _user: Any = Depends(get_current_user),
    ) -> Any:
        """Return detailed diagnostics for a single scanner."""
        s = _discovery.get_scanner_status(scanner_id)
        if not s.installed and s.availability_reason and "Unknown" in s.availability_reason:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown scanner: {scanner_id!r}",
            )
        guide = _installer.get_guide(scanner_id)
        best_cmd = _installer.get_install_command(scanner_id)

        if fmt == "markdown":
            content = _diagnostics_to_markdown(s, guide, best_cmd)
            return PlainTextResponse(content, media_type="text/markdown")
        elif fmt == "text":
            content = _diagnostics_to_text(s, guide, best_cmd)
            return PlainTextResponse(content, media_type="text/plain")
        return _diagnostics_to_dict(s, guide, best_cmd)

    # ── GET /scanners/{scanner_id}/install ───────────────────────────────

    @router.get("/{scanner_id}/install")
    async def get_scanner_install_commands(
        scanner_id: Annotated[
            str,
            Path(
                description="Scanner identifier (e.g. nmap, nuclei, trivy)",
                pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
            ),
        ],
        _user: Any = Depends(get_current_user),
    ) -> dict[str, Any]:
        """Return installation commands for a scanner."""
        guide = _installer.get_guide(scanner_id)
        if guide is None:
            raise HTTPException(status_code=404, detail=f"Unknown scanner: {scanner_id!r}")
        commands = _installer.get_all_commands(scanner_id)
        best = _installer.get_install_command(scanner_id)
        return {
            "scanner_id": scanner_id,
            "name": guide.name,
            "platform": _installer.detect_platform(),
            "available_package_managers": list(_installer.detect_package_managers()),
            "commands": [
                {
                    "manager": cmd.manager,
                    "command": cmd.command,
                    "description": cmd.description,
                    "requires_admin": cmd.requires_admin,
                }
                for cmd in commands
            ],
            "best_command": {
                "manager": best.manager,
                "command": best.command,
                "description": best.description,
                "requires_admin": best.requires_admin,
            } if best else None,
            "verify_command": guide.verify_command,
            "website": guide.website,
            "min_version": guide.min_version,
            "expected_binary": guide.expected_binary,
        }

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
        "permissions_ok": st.permissions_ok,
        "recommendations": list(st.recommendations),
    }


def _diagnostics_to_dict(st: Any, guide: Any, best_cmd: Any) -> dict[str, Any]:
    """Convert scanner status + install guide to a diagnostics dict."""
    return {
        "scanner_id": st.scanner_id,
        "name": st.name,
        "status": "usable" if st.usable else ("installed" if st.installed else "missing"),
        "installed": st.installed,
        "executable_path": st.executable_path,
        "version": st.version,
        "usable": st.usable,
        "availability_reason": st.availability_reason,
        "warnings": list(st.warnings),
        "required_assets": list(st.required_assets),
        "missing_assets": list(st.missing_assets),
        "permissions_ok": st.permissions_ok,
        "recommendations": list(st.recommendations),
        "install_hints": list(st.install_hints),
        "installation": {
            "website": guide.website if guide else "",
            "min_version": guide.min_version if guide else "",
            "verify_command": guide.verify_command if guide else "",
            "best_command": {
                "manager": best_cmd.manager,
                "command": best_cmd.command,
            } if best_cmd else None,
            "known_issues": list(guide.known_issues) if guide and guide.known_issues else [],
        } if guide else None,
    }


def _diagnostics_to_markdown(st: Any, guide: Any, best_cmd: Any) -> str:
    """Convert scanner diagnostics to Markdown."""
    lines = [f"# Scanner Diagnostics: {st.name} ({st.scanner_id})", ""]
    lines.append(f"**Status:** {'Usable' if st.usable else 'Installed (partial)' if st.installed else 'Missing'}")
    lines.append(f"**Installed:** {'Yes' if st.installed else 'No'}")
    if st.version:
        lines.append(f"**Version:** {st.version}")
    if st.executable_path:
        lines.append(f"**Executable:** {st.executable_path}")
    lines.append(f"**Permissions OK:** {'Yes' if st.permissions_ok else 'No'}")
    lines.append("")

    if st.warnings:
        lines.append("## Warnings")
        for w in st.warnings:
            lines.append(f"- {w}")
        lines.append("")

    if st.recommendations:
        lines.append("## Recommendations")
        for r in st.recommendations:
            lines.append(f"- {r}")
        lines.append("")

    if st.missing_assets:
        lines.append("## Missing Assets")
        for a in st.missing_assets:
            lines.append(f"- {a}")
        lines.append("")

    if guide:
        lines.append("## Installation")
        lines.append(f"- Website: {guide.website}")
        lines.append(f"- Minimum version: {guide.min_version}")
        lines.append(f"- Verify: `{guide.verify_command}`")
        if best_cmd:
            lines.append(f"- Install: `{best_cmd.command}`")
        if guide.known_issues:
            lines.append("")
            lines.append("### Known Issues")
            for issue in guide.known_issues:
                lines.append(f"- {issue}")
    lines.append("")

    if st.install_hints:
        lines.append("## Install Hints")
        for h in st.install_hints:
            lines.append(f"- {h}")
        lines.append("")

    return "\n".join(lines)


def _diagnostics_to_text(st: Any, guide: Any, best_cmd: Any) -> str:
    """Convert scanner diagnostics to plain text."""
    lines = [f"Scanner Diagnostics: {st.name} ({st.scanner_id})", "=" * 50, ""]
    lines.append(f"  Status:          {'Usable' if st.usable else 'Installed (partial)' if st.installed else 'Missing'}")
    lines.append(f"  Installed:       {'Yes' if st.installed else 'No'}")
    if st.version:
        lines.append(f"  Version:         {st.version}")
    if st.executable_path:
        lines.append(f"  Executable:      {st.executable_path}")
    lines.append(f"  Permissions OK:  {'Yes' if st.permissions_ok else 'No'}")
    lines.append("")

    if st.warnings:
        lines.append("  Warnings:")
        for w in st.warnings:
            lines.append(f"    - {w}")
        lines.append("")

    if st.recommendations:
        lines.append("  Recommendations:")
        for r in st.recommendations:
            lines.append(f"    - {r}")
        lines.append("")

    if st.missing_assets:
        lines.append("  Missing Assets:")
        for a in st.missing_assets:
            lines.append(f"    - {a}")
        lines.append("")

    if guide:
        lines.append("  Installation:")
        lines.append(f"    Website:          {guide.website}")
        lines.append(f"    Minimum version:  {guide.min_version}")
        lines.append(f"    Verify command:   {guide.verify_command}")
        if best_cmd:
            lines.append(f"    Install command:  {best_cmd.command}")
        if guide.known_issues:
            lines.append("  Known Issues:")
            for issue in guide.known_issues:
                lines.append(f"    - {issue}")

    return "\n".join(lines)
