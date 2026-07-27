"""Scanner Discovery Service.

Application-layer service that detects installed scanners, validates their
executables and required assets, and produces a structured health report.

This service does NOT execute arbitrary commands — it uses the existing
scanner plugins' ``is_available()`` and safe subprocess calls to extract
version information. It never installs or modifies anything.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssetRequirement:
    """One required asset for a scanner (template dir, wordlist, DB, etc.)."""

    name: str
    kind: str  # "file", "directory", "command"
    path: str | None = None
    install_hint: str = ""
    optional: bool = False


@dataclass(frozen=True, slots=True)
class ScannerStatus:
    """Discovery status for a single scanner."""

    scanner_id: str
    name: str
    installed: bool
    executable_path: str | None
    version: str | None
    usable: bool
    availability_reason: str | None
    warnings: tuple[str, ...] = ()
    required_assets: tuple[str, ...] = ()
    missing_assets: tuple[str, ...] = ()
    install_hints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerHealthReport:
    """Aggregate health report across all scanners."""

    total: int
    installed: int
    usable: int
    partial: int
    missing: int
    health_score: float
    scanners: tuple[ScannerStatus, ...]


# ---------------------------------------------------------------------------
# Scanner manifest — defines how each scanner is discovered and validated
# ---------------------------------------------------------------------------

PlatformHint = str  # "windows" | "linux" | "macos"

_INSTALL_HINTS: dict[str, dict[PlatformHint, str]] = {
    "nmap": {
        "windows": "choco install nmap  (or  winget install Insecure.Nmap)",
        "linux": "apt install nmap  (or  sudo apt-get install nmap)",
    },
    "nuclei": {
        "windows": "Download from https://github.com/projectdiscovery/nuclei/releases  (or  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)",
        "linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  (or  apt install nuclei)",
    },
    "nikto": {
        "windows": "Download from https://github.com/sullo/nikto/releases",
        "linux": "apt install nikto",
    },
    "ffuf": {
        "windows": "Download from https://github.com/ffuf/ffuf/releases  (or  go install github.com/ffuf/ffuf/v2@latest)",
        "linux": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "gobuster": {
        "windows": "Download from https://github.com/OJ/gobuster/releases  (or  go install github.com/OJ/gobuster/v3@latest)",
        "linux": "go install github.com/OJ/gobuster/v3@latest",
    },
    "trivy": {
        "windows": "choco install trivy  (or  winget install AquaSecurity.Trivy)",
        "linux": "apt install trivy  (or  sudo apt-get install trivy)",
    },
    "semgrep": {
        "windows": "pip install semgrep",
        "linux": "pip install semgrep  (or  apt install semgrep)",
    },
    "amass": {
        "windows": "Download from https://github.com/owasp-amass/amass/releases  (or  go install -v github.com/owasp-amass/amass/v4/...@master)",
        "linux": "go install -v github.com/owasp-amass/amass/v4/...@master",
    },
    "zap": {
        "windows": "Download from https://www.zaproxy.org/download/",
        "linux": "docker run -d --name zap ghcr.io/zaproxy/zaproxy:stable  (or  apt install zaproxy)",
    },
}

_SCANNER_MANIFEST: dict[str, dict[str, Any]] = {
    "nmap": {
        "name": "Nmap",
        "binary": "nmap",
        "version_args": ("--version",),
        "version_regex": r"version\s+([\d.]+)",
        "assets": [],
    },
    "nuclei": {
        "name": "Nuclei",
        "binary": "nuclei",
        "version_args": ("-version",),
        "version_regex": r"([\d.]+)",
        "assets": [
            AssetRequirement(
                name="Nuclei templates",
                kind="directory",
                path=str(Path.home() / "nuclei-templates"),
                install_hint="nuclei -update-templates",
            ),
        ],
    },
    "nikto": {
        "name": "Nikto",
        "binary": "nikto",
        "version_args": ("-Version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
    },
    "ffuf": {
        "name": "FFUF",
        "binary": "ffuf",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
    },
    "gobuster": {
        "name": "Gobuster",
        "binary": "gobuster",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
    },
    "trivy": {
        "name": "Trivy",
        "binary": "trivy",
        "version_args": ("--version",),
        "version_regex": r"Version:\s*([\d.]+)",
        "assets": [
            AssetRequirement(
                name="Trivy vulnerability DB",
                kind="directory",
                path=str(Path.home() / ".cache" / "trivy" / "db"),
                install_hint="trivy image --download-db-only",
                optional=True,
            ),
        ],
    },
    "semgrep": {
        "name": "Semgrep",
        "binary": "semgrep",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
    },
    "amass": {
        "name": "Amass",
        "binary": "amass",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
    },
    "zap": {
        "name": "OWASP ZAP",
        "binary": "zap",
        "version_args": ("-version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
    },
}


# ---------------------------------------------------------------------------
# Platform utilities
# ---------------------------------------------------------------------------


def _current_platform() -> PlatformHint:
    p = sys.platform
    if "win" in p:
        return "windows"
    if "linux" in p:
        return "linux"
    return "macos"


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def _find_executable(binary: str) -> str | None:
    """Locate a binary using ``shutil.which`` with platform-specific PATH.

    On Windows, also checks Chocolatey and Scoop install locations.
    On Linux, also checks /snap/bin and common package paths.
    On macOS, also checks /opt/homebrew/bin and /usr/local/bin.
    """
    found = shutil.which(binary)
    if found is not None:
        return found

    platform = _current_platform()
    extra_paths: list[str] = []

    if platform == "windows":
        extra_paths.extend([
            rf"C:\ProgramData\chocolatey\bin\{binary}.exe",
            rf"C:\ProgramData\chocolatey\lib\{binary}\tools\{binary}.exe",
            rf"{Path.home()}\scoop\apps\{binary}\current\{binary}.exe",
            rf"{Path.home()}\AppData\Local\Microsoft\WinGet\Links\{binary}.exe",
            rf"C:\Program Files\{binary}\{binary}.exe",
            rf"C:\Program Files (x86)\{binary}\{binary}.exe",
            rf"{Path.home()}\AppData\Local\Programs\{binary}\{binary}.exe",
        ])
    elif platform == "linux":
        extra_paths.extend([
            f"/snap/bin/{binary}",
            f"/usr/local/bin/{binary}",
            f"/usr/bin/{binary}",
            f"/opt/{binary}/bin/{binary}",
            f"{Path.home()}/go/bin/{binary}",
            f"{Path.home()}/.local/bin/{binary}",
        ])
    elif platform == "macos":
        extra_paths.extend([
            f"/opt/homebrew/bin/{binary}",
            f"/usr/local/bin/{binary}",
            f"{Path.home()}/go/bin/{binary}",
            f"{Path.home()}/.local/bin/{binary}",
        ])

    for p in extra_paths:
        candidate = Path(p)
        if candidate.is_file():
            return str(candidate.resolve())

    return None


def _get_version(path: str, args: tuple[str, ...], regex: str) -> str | None:
    """Safely run ``<path> <args>`` and extract a version from stderr+stdout.

    Uses ``subprocess.run`` with ``shell=False`` (list-based invocation),
    a short timeout, and captures combined stdout+stderr.
    """
    try:
        result = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        match = re.search(regex, combined, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _check_asset(asset: AssetRequirement) -> bool:
    """Check whether an asset requirement is satisfied."""
    if not asset.path:
        return False
    p = Path(asset.path)
    if asset.kind == "file":
        return p.is_file()
    if asset.kind == "directory":
        return p.is_dir()
    return False


# ---------------------------------------------------------------------------
# Public service
# ---------------------------------------------------------------------------


class ScannerDiscoveryService:
    """Discover and validate scanner installations on the current system."""

    def get_scanner_status(self, scanner_id: str) -> ScannerStatus:
        """Discover the status of a single scanner."""
        manifest = _SCANNER_MANIFEST.get(scanner_id)
        if manifest is None:
            return ScannerStatus(
                scanner_id=scanner_id,
                name=scanner_id,
                installed=False,
                executable_path=None,
                version=None,
                usable=False,
                availability_reason=f"Unknown scanner: {scanner_id!r}",
                required_assets=(),
                missing_assets=(),
            )

        name: str = manifest["name"]
        binary: str = manifest["binary"]
        version_args: tuple[str, ...] = manifest["version_args"]
        version_regex: str = manifest["version_regex"]
        assets: list[AssetRequirement] = manifest["assets"]

        path = _find_executable(binary)
        if path is None:
            hints = _INSTALL_HINTS.get(scanner_id, {})
            hint = hints.get(_current_platform(), "")
            return ScannerStatus(
                scanner_id=scanner_id,
                name=name,
                installed=False,
                executable_path=None,
                version=None,
                usable=False,
                availability_reason=f"{binary!r} not found on PATH or common locations",
                required_assets=tuple(a.name for a in assets if not a.optional),
                missing_assets=(),
                install_hints=(hint,) if hint else (),
            )

        version = _get_version(path, version_args, version_regex)

        warnings: list[str] = []
        missing_assets: list[str] = []
        for asset in assets:
            if not _check_asset(asset):
                missing_assets.append(asset.name)
                if not asset.optional:
                    warnings.append(f"Missing {asset.name}: {asset.install_hint}")

        usable = len(missing_assets) == 0 or all(
            a.optional for a in assets if a.name in missing_assets
        )

        all_asset_names = tuple(a.name for a in assets if not a.optional)
        missing_names = tuple(missing_assets)
        hints = _INSTALL_HINTS.get(scanner_id, {})
        hint = hints.get(_current_platform(), "")
        install_hints = [hint] if hint else []
        for asset in assets:
            if asset.path and not Path(asset.path).exists():
                if asset.install_hint:
                    install_hints.append(asset.install_hint)

        return ScannerStatus(
            scanner_id=scanner_id,
            name=name,
            installed=True,
            executable_path=path,
            version=version or None,
            usable=usable,
            availability_reason=None if usable else "; ".join(warnings) or None,
            warnings=tuple(warnings),
            required_assets=all_asset_names,
            missing_assets=missing_names,
            install_hints=tuple(install_hints),
        )

    def get_all_statuses(self) -> tuple[ScannerStatus, ...]:
        """Return status for every known scanner."""
        return tuple(
            self.get_scanner_status(scanner_id)
            for scanner_id in sorted(_SCANNER_MANIFEST)
        )

    def get_health_report(self) -> ScannerHealthReport:
        """Produce an aggregate health report across all scanners."""
        scanners = self.get_all_statuses()
        total = len(scanners)
        installed = sum(1 for s in scanners if s.installed)
        usable = sum(1 for s in scanners if s.usable)
        partial = sum(
            1
            for s in scanners
            if s.installed and not s.usable and s.missing_assets
        )
        missing = total - installed

        score = (usable / total * 100) if total > 0 else 0.0

        return ScannerHealthReport(
            total=total,
            installed=installed,
            usable=usable,
            partial=partial,
            missing=missing,
            health_score=round(score, 1),
            scanners=scanners,
        )
