"""Plugin sandboxing: filesystem restrictions, execution limits, safe cleanup.

Provides runtime isolation for plugin execution without process-level
sandboxing. Enforces:
- Filesystem path restrictions (read/write allowed paths only)
- Execution timeout enforcement
- Memory limit tracking
- Temporary working directory lifecycle
- Permission enforcement before operations
- Safe cleanup on completion or failure
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from kingsec.infrastructure.logging import get_logger

logger = get_logger("kingsec.plugin.sandbox")

# Default limits
DEFAULT_EXECUTION_TIMEOUT = 300  # 5 minutes
DEFAULT_MEMORY_LIMIT_MB = 256
DEFAULT_MAX_OPEN_FILES = 64
MAX_PLUGIN_INSTALL_SIZE_MB = 100


class SandboxViolation(Exception):
    """Raised when a plugin attempts a disallowed operation."""


class ExecutionTimeout(Exception):
    """Raised when a plugin exceeds its execution time limit."""


class MemoryLimitExceeded(Exception):
    """Raised when a plugin exceeds its memory limit."""


class PluginSandbox:
    """Enforces runtime restrictions on a single plugin execution context.

    Each plugin instance gets its own sandbox with:
    - Allowed filesystem paths (read and write)
    - Execution timeout
    - Memory limit tracking
    - Temporary working directory (cleaned up automatically)
    - Permission checker reference
    """

    def __init__(
        self,
        plugin_id: str,
        *,
        allowed_read_paths: tuple[Path, ...] = (),
        allowed_write_paths: tuple[Path, ...] = (),
        execution_timeout: int = DEFAULT_EXECUTION_TIMEOUT,
        memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        temp_dir: Path | None = None,
    ) -> None:
        self._plugin_id = plugin_id
        self._allowed_read = frozenset(p.resolve() for p in allowed_read_paths)
        self._allowed_write = frozenset(p.resolve() for p in allowed_write_paths)
        self._execution_timeout = execution_timeout
        self._memory_limit_mb = memory_limit_mb
        self._temp_dir = temp_dir
        self._temp_dir_created = False
        self._start_time: float | None = None
        self._lock = threading.Lock()
        self._cleanup_registered = False

    @property
    def plugin_id(self) -> str:
        return self._plugin_id

    @property
    def temp_dir(self) -> Path:
        """Return the temporary working directory, creating it if needed."""
        if self._temp_dir is None:
            self._temp_dir = Path(tempfile.mkdtemp(prefix=f"kingsec_plugin_{self._plugin_id}_"))
            self._temp_dir_created = True
        return self._temp_dir

    def check_timeout(self) -> None:
        """Raise ExecutionTimeout if the plugin has exceeded its time limit."""
        if self._start_time is not None:
            elapsed = time.monotonic() - self._start_time
            if elapsed > self._execution_timeout:
                raise ExecutionTimeout(
                    f"Plugin '{self._plugin_id}' exceeded execution timeout "
                    f"({self._execution_timeout}s, elapsed: {elapsed:.1f}s)"
                )

    def check_memory(self) -> None:
        """Check current process memory against the limit (best-effort)."""
        try:
            import resource as _resource

            usage = _resource.getrusage(_resource.RUSAGE_SELF)  # type: ignore[attr-defined]
            mem_mb = usage.ru_maxrss / 1024  # Linux: KB -> MB
            if mem_mb > self._memory_limit_mb:
                raise MemoryLimitExceeded(
                    f"Plugin '{self._plugin_id}' exceeded memory limit "
                    f"({self._memory_limit_mb}MB, usage: {mem_mb:.0f}MB)"
                )
        except (ImportError, AttributeError, ValueError):
            # resource module not available on all platforms (e.g. Windows)
            pass

    def validate_file_access(self, path: str | Path, for_write: bool = False) -> None:
        """Validate that a file access is within allowed paths.

        Raises SandboxViolation if the path is not allowed.
        """
        resolved = Path(path).resolve()
        if for_write:
            if not any(resolved.is_relative_to(p) for p in self._allowed_write):
                raise SandboxViolation(
                    f"Plugin '{self._plugin_id}' denied write access to {resolved}"
                )
        else:
            if not any(resolved.is_relative_to(p) for p in self._allowed_read):
                raise SandboxViolation(
                    f"Plugin '{self._plugin_id}' denied read access to {resolved}"
                )

    def validate_network_access(self, url: str) -> None:
        """Validate that a network URL is allowed (basic scheme check)."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SandboxViolation(
                f"Plugin '{self._plugin_id}' denied network access to non-HTTP(S) URL: {url}"
            )
        from kingsec.infrastructure.security.input_validation import validate_url_for_ssrf

        try:
            validate_url_for_ssrf(url)
        except ValueError as exc:
            raise SandboxViolation(
                f"Plugin '{self._plugin_id}' denied network access: {exc}"
            ) from exc

    def start(self) -> None:
        """Mark the sandbox as active (start timeout tracking)."""
        with self._lock:
            self._start_time = time.monotonic()
        logger.info(
            "sandbox started for plugin %s (timeout=%ds, memory=%dMB)",
            self._plugin_id,
            self._execution_timeout,
            self._memory_limit_mb,
        )

    def stop(self) -> None:
        """Mark the sandbox as inactive and clean up temporary resources."""
        with self._lock:
            self._start_time = None
        self.cleanup()
        logger.info("sandbox stopped for plugin %s", self._plugin_id)

    def cleanup(self) -> None:
        """Remove temporary directory and its contents."""
        if self._temp_dir and self._temp_dir_created and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                logger.debug("cleaned up temp dir for plugin %s", self._plugin_id)
            except Exception as exc:
                logger.warning(
                    "failed to clean up temp dir for plugin %s: %s",
                    self._plugin_id,
                    exc,
                )

    def __enter__(self) -> PluginSandbox:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    def __del__(self) -> None:
        self.cleanup()


def build_sandbox_for_plugin(
    plugin_id: str,
    permissions: tuple[str, ...],
    data_dir: Path,
    *,
    execution_timeout: int = DEFAULT_EXECUTION_TIMEOUT,
    memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
) -> PluginSandbox:
    """Build a sandbox configuration from declared permissions.

    Maps permission strings to allowed filesystem paths:
    - FILESYSTEM_READ: data_dir/plugins/{plugin_id} (read-only)
    - FILESYSTEM_WRITE: data_dir/plugins/{plugin_id}/output (write)
    - NETWORK: validated via SSRF checks (no extra paths needed)
    """
    plugin_base = data_dir / "plugins" / plugin_id
    allowed_read = [plugin_base]
    allowed_write: list[Path] = []

    if "filesystem_write" in permissions:
        output_dir = plugin_base / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        allowed_write.append(output_dir)
    if "filesystem_read" in permissions:
        allowed_read.append(data_dir / "data")

    return PluginSandbox(
        plugin_id,
        allowed_read_paths=tuple(allowed_read),
        allowed_write_paths=tuple(allowed_write),
        execution_timeout=execution_timeout,
        memory_limit_mb=memory_limit_mb,
    )
