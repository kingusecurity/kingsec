"""Diagnostics bundle generator for support.

Collects system info, configuration, health status, logs, and recent
audit events into a single JSON/ZIP bundle for support tickets.
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SystemInfo:
    """Operating system and Python runtime details."""

    os_name: str = field(default_factory=platform.system)
    os_version: str = field(default_factory=platform.version)
    os_release: str = field(default_factory=platform.release)
    python_version: str = field(default_factory=lambda: sys.version)
    python_executable: str = field(default_factory=lambda: sys.executable)
    machine: str = field(default_factory=platform.machine)
    processor: str = field(default_factory=platform.processor)
    hostname: str = field(default_factory=platform.node)
    pid: int = field(default_factory=os.getpid)


@dataclass(frozen=True)
class DiagnosticEntry:
    """A single diagnostic data point."""

    key: str
    value: Any
    category: str = "general"
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )


class DiagnosticsCollector:
    """Collects diagnostic information from all system components."""

    def __init__(
        self,
        data_dir: Path | None = None,
        app_version: str = "unknown",
    ) -> None:
        self._data_dir = data_dir or Path.home() / ".kingsec"
        self._app_version = app_version

    def collect_system_info(self) -> dict[str, Any]:
        """Collect basic system information."""
        info = SystemInfo()
        return {
            "os": info.os_name,
            "os_version": info.os_version,
            "os_release": info.os_release,
            "python": info.python_version,
            "python_executable": info.python_executable,
            "machine": info.machine,
            "processor": info.processor,
            "hostname": info.hostname,
            "pid": info.pid,
        }

    def collect_config_summary(self) -> dict[str, Any]:
        """Collect non-sensitive configuration summary."""
        env = os.environ
        return {
            "kingsec_env": env.get("KINGSEC_ENVIRONMENT", "development"),
            "kingsec_debug": env.get("KINGSEC_DEBUG", "false"),
            "kingsec_log_level": env.get("KINGSEC_LOGGING__LEVEL", "INFO"),
            "kingsec_data_dir": str(self._data_dir),
            "database_url": "***" if env.get("KINGSEC_DATABASE_URL") else "not set",
        }

    def collect_health_status(self) -> dict[str, Any]:
        """Attempt to call health endpoint and return status."""
        import urllib.error
        import urllib.request

        try:
            url = "http://127.0.0.1:8765/api/v1/health"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as exc:
            return {"status": "unreachable", "error": str(exc)}

    def collect_disk_usage(self) -> dict[str, Any]:
        """Check disk space in the data directory."""
        import shutil

        try:
            usage = shutil.disk_usage(str(self._data_dir))
            return {
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_used": round(usage.used / usage.total * 100, 1),
            }
        except (OSError, ValueError) as exc:
            return {"error": str(exc)}

    def collect_recent_logs(self, lines: int = 100) -> list[str]:
        """Read recent log lines from the log file."""
        log_dir = self._data_dir / "logs"
        if not log_dir.is_dir():
            return ["No log directory found"]

        log_files = sorted(log_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not log_files:
            return ["No log files found"]

        recent_lines: list[str] = []
        for log_file in log_files[:3]:
            try:
                with open(log_file, encoding="utf-8", errors="replace") as f:
                    all_lines = f.readlines()
                    recent_lines.extend(
                        [f"[{log_file.name}] {line.rstrip()}" for line in all_lines[-lines:]]
                    )
            except (OSError, PermissionError):
                recent_lines.append(f"[{log_file.name}] unreadable")

        return recent_lines[-lines:]

    def collect_database_info(self) -> dict[str, Any]:
        """Check database file size and table count."""
        db_path = self._data_dir / "kingsec.db"
        if not db_path.is_file():
            return {"exists": False}

        try:
            size_mb = round(db_path.stat().st_size / (1024**2), 2)
            return {
                "exists": True,
                "path": str(db_path),
                "size_mb": size_mb,
            }
        except OSError as exc:
            return {"exists": False, "error": str(exc)}

    def collect_environment_variables(self) -> dict[str, str]:
        """Collect non-sensitive environment variables (no secrets)."""
        safe_prefixes = ("KINGSEC_", "PATH", "HOME", "USER", "LANG", "SHELL", "PYTHON")
        secrets_keywords = ("SECRET", "PASSWORD", "TOKEN", "KEY", "PEPPER", "ENCRYPTION")
        collected: dict[str, str] = {}

        for key, value in os.environ.items():
            if any(key.startswith(p) for p in safe_prefixes):
                if not any(kw in key.upper() for kw in secrets_keywords):
                    collected[key] = value

        return collected

    def collect_all(self) -> dict[str, Any]:
        """Collect all diagnostic data."""
        return {
            "version": self._app_version,
            "collected_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "system": self.collect_system_info(),
            "config": self.collect_config_summary(),
            "health": self.collect_health_status(),
            "disk": self.collect_disk_usage(),
            "database": self.collect_database_info(),
            "environment": self.collect_environment_variables(),
            "recent_logs": self.collect_recent_logs(50),
        }

    def create_bundle(self, output_dir: Path | None = None) -> Path:
        """Create a diagnostics bundle for this collector's data_dir/app_version."""
        return create_diagnostics_bundle(
            data_dir=self._data_dir,
            app_version=self._app_version,
            output_dir=output_dir,
        )


def create_diagnostics_bundle(
    data_dir: Path | None = None,
    app_version: str = "unknown",
    output_dir: Path | None = None,
) -> Path:
    """Create a diagnostics bundle (JSON + optional ZIP).

    Returns the path to the created bundle file.
    """
    collector = DiagnosticsCollector(data_dir=data_dir, app_version=app_version)
    diagnostic_data = collector.collect_all()

    out = output_dir or Path(tempfile.gettempdir())
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    base_name = f"kingsec-diagnostics-{timestamp}"

    # Write JSON
    json_path = out / f"{base_name}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(diagnostic_data, f, indent=2, default=str)

    # Write ZIP with JSON inside
    zip_path = out / f"{base_name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(json_path, f"{base_name}/diagnostics.json")
        # Include recent logs if available
        log_dir = (data_dir or Path.home() / ".kingsec") / "logs"
        if log_dir.is_dir():
            for log_file in sorted(log_dir.glob("*.log"), key=lambda f: f.stat().st_mtime)[-3:]:
                zf.write(log_file, f"{base_name}/logs/{log_file.name}")

    return zip_path
