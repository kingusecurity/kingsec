from __future__ import annotations

from pathlib import Path

from kingsec.domain.system_health import HealthCheck, HealthStatus


class FilesystemHealthCheck:
    def __init__(self, path: str | Path = ".") -> None:
        self._path = Path(path)

    def check(self) -> HealthCheck:
        try:
            test_file = self._path / ".health_check_tmp"
            test_file.write_text("ok")
            test_file.unlink()
            usage = 0.0
            try:
                import shutil
                total, used, free = shutil.disk_usage(self._path)
                usage = (used / total) * 100
            except (ImportError, AttributeError):
                pass
            status = HealthStatus.DEGRADED if usage > 90 else HealthStatus.HEALTHY
            return HealthCheck(
                name="filesystem",
                status=status,
                message=f"Disk usage: {usage:.1f}%" if usage > 0 else "Filesystem writable",
            )
        except Exception as exc:
            return HealthCheck(name="filesystem", status=HealthStatus.UNHEALTHY, message=str(exc))


class DatabaseHealthCheck:
    def __init__(self, session_factory=None) -> None:
        self._session_factory = session_factory

    def check(self) -> HealthCheck:
        if not self._session_factory:
            return HealthCheck(name="database", status=HealthStatus.HEALTHY, message="No database configured")
        try:
            from sqlalchemy import text
            with self._session_factory() as session:
                result = session.execute(text("SELECT 1")).scalar()
                if result == 1:
                    return HealthCheck(name="database", status=HealthStatus.HEALTHY, message="Database reachable")
                return HealthCheck(name="database", status=HealthStatus.UNHEALTHY, message="Database returned unexpected result")
        except Exception as exc:
            return HealthCheck(name="database", status=HealthStatus.UNHEALTHY, message=str(exc))
