"""Scanner Discovery Service.

Application-layer service that detects installed scanners, validates their
executables and required assets, and produces a structured health report.

This service does NOT execute arbitrary commands — it uses the existing
scanner plugins' ``is_available()`` and safe subprocess calls to extract
version information. It never installs or modifies anything.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 -- see _get_version()/_check_java() for the justification
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
    permissions_ok: bool = True
    recommendations: tuple[str, ...] = ()
    has_templates: bool = False
    has_perl: bool = False
    has_java: bool = False
    has_wordlists: bool = False


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
        "extra_checks": {
            "required_permissions": True,
        },
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
            AssetRequirement(
                name="Nuclei template config",
                kind="file",
                path=str(Path.home() / ".config" / "nuclei" / ".templates-config.json"),
                install_hint="nuclei -update-templates",
                optional=True,
            ),
        ],
        "extra_checks": {
            "has_templates": True,
        },
    },
    "nikto": {
        "name": "Nikto",
        "binary": "nikto",
        "version_args": ("-Version",),
        "version_regex": r"([\d.]+)",
        "assets": [
            AssetRequirement(
                name="Perl runtime",
                kind="command",
                path=None,
                install_hint="Install Perl from https://www.perl.org/get.html",
            ),
        ],
        "extra_checks": {
            "check_perl": True,
        },
    },
    "ffuf": {
        "name": "FFUF",
        "binary": "ffuf",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        # Phase 2A Correction 4: path is None here deliberately — the real
        # path comes from the operator-configured FfufSettings.wordlist at
        # request time (see get_scanner_status()'s wordlist substitution
        # below), never this hardcoded Linux default. A missing wordlist
        # is now a real, required asset (optional=False) matching Nuclei's
        # templates requirement, not a silently-ignored one.
        "assets": [
            AssetRequirement(
                name="Wordlist file",
                kind="file",
                path=None,
                install_hint="Configure KINGSEC_FFUF__WORDLIST, e.g. a SecLists path: https://github.com/danielmiessler/SecLists",
            ),
        ],
        "extra_checks": {},
    },
    "gobuster": {
        "name": "Gobuster",
        "binary": "gobuster",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        # Same as ffuf above: real path substituted from
        # GobusterSettings.wordlist at request time.
        "assets": [
            AssetRequirement(
                name="Wordlist file",
                kind="file",
                path=None,
                install_hint="Configure KINGSEC_GOBUSTER__WORDLIST, e.g. a SecLists path: https://github.com/danielmiessler/SecLists",
            ),
        ],
        "extra_checks": {},
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
        "extra_checks": {},
    },
    "semgrep": {
        "name": "Semgrep",
        "binary": "semgrep",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        "assets": [],
        "extra_checks": {},
    },
    "amass": {
        "name": "Amass",
        "binary": "amass",
        "version_args": ("--version",),
        "version_regex": r"([\d.]+)",
        "assets": [
            AssetRequirement(
                name="Amass config directory",
                kind="directory",
                path=str(Path.home() / ".amass"),
                install_hint="mkdir -p ~/.amass  or  amass enum -list",
                optional=True,
            ),
        ],
        "extra_checks": {},
    },
    "zap": {
        "name": "OWASP ZAP",
        "binary": "zap",
        "version_args": ("-version",),
        "version_regex": r"([\d.]+)",
        "assets": [
            AssetRequirement(
                name="Java runtime",
                kind="command",
                path=None,
                install_hint="Install Java 11+ from https://adoptium.net",
            ),
        ],
        "extra_checks": {
            "check_java": True,
        },
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
        # path is a filesystem path resolved by _find_executable() via a
        # fixed search over well-known install locations for a hardcoded
        # binary name (from _SCANNER_MANIFEST, a static dict literal - see
        # line 119); args is that same manifest entry's hardcoded
        # version_args tuple (e.g. ("--version",)). Neither is ever derived
        # from a scan target, request body, or other caller-supplied value -
        # scanner_id only selects among the fixed manifest keys and cannot
        # influence the command vector itself.
        result = subprocess.run(  # nosec B603
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
    if asset.kind == "command":
        return shutil.which(asset.name.split()[0].lower()) is not None
    if not asset.path:
        return False
    p = Path(asset.path)
    if asset.kind == "file":
        return p.is_file()
    if asset.kind == "directory":
        return p.is_dir()
    return False


def _check_permissions(path: str | None) -> bool:
    """Check if a binary has execute permissions."""
    if path is None:
        return False
    p = Path(path)
    if not p.is_file():
        return False
    return os.access(p, os.X_OK)


def _check_java() -> bool:
    """Check if Java runtime is available."""
    java = shutil.which("java")
    if java is None:
        return False
    try:
        # java is shutil.which("java")'s own resolved path (a fixed,
        # hardcoded binary name), and "-version" is a literal. Same
        # reasoning as _get_version() above: no caller-supplied value
        # reaches this command vector.
        result = subprocess.run(  # nosec B603
            [java, "-version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        match = re.search(r'(?:version|openjdk version)\s+"?(\d+)', combined)
        if match:
            major = int(match.group(1))
            return major >= 11
        return False
    except (OSError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Public service
# ---------------------------------------------------------------------------


class ScannerDiscoveryService:
    """Discover and validate scanner installations on the current system.

    Phase 2A Correction 4: ``ffuf_wordlist``/``gobuster_wordlist`` are the
    operator's actual configured ``FfufSettings.wordlist`` /
    ``GobusterSettings.wordlist`` values. Without them, discovery has no
    way to know whether a real wordlist is configured and correctly
    reports the asset as missing on every platform — including Windows,
    where the old hardcoded ``/usr/share/wordlists`` check would have
    reported "missing" unconditionally regardless of configuration the
    moment this requirement became non-optional.
    """

    def __init__(self, *, ffuf_wordlist: str = "", gobuster_wordlist: str = "") -> None:
        self._ffuf_wordlist = ffuf_wordlist
        self._gobuster_wordlist = gobuster_wordlist

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
        # Copy, never mutate the shared module-level manifest list — and
        # substitute the real configured wordlist path for ffuf/gobuster
        # (Correction 4) rather than checking a hardcoded Linux directory
        # that has nothing to do with what the operator actually set.
        assets: list[AssetRequirement] = list(manifest["assets"])
        if scanner_id == "ffuf" and assets:
            assets = [
                AssetRequirement(
                    name=assets[0].name,
                    kind=assets[0].kind,
                    path=self._ffuf_wordlist or None,
                    install_hint=assets[0].install_hint,
                    optional=assets[0].optional,
                )
            ]
        elif scanner_id == "gobuster" and assets:
            assets = [
                AssetRequirement(
                    name=assets[0].name,
                    kind=assets[0].kind,
                    path=self._gobuster_wordlist or None,
                    install_hint=assets[0].install_hint,
                    optional=assets[0].optional,
                )
            ]

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

        extra = manifest.get("extra_checks", {})

        permissions_ok = _check_permissions(path)

        has_templates = bool(
            Path.home().joinpath("nuclei-templates").is_dir()
        ) if scanner_id == "nuclei" else False
        has_perl = shutil.which("perl") is not None if scanner_id == "nikto" else False
        has_java = _check_java() if scanner_id == "zap" else False
        # Phase 2A Correction 4: reflects the same real, configured
        # wordlist path already substituted into `assets` above — not the
        # old hardcoded Linux-only directory check, which would have
        # reported "missing" on every Windows host regardless of
        # configuration.
        has_wordlists = (
            "Wordlist file" not in missing_assets
        ) if scanner_id in ("ffuf", "gobuster") else False

        if extra.get("required_permissions") and not permissions_ok:
            warnings.append(f"{binary!r} may need elevated privileges for full functionality")

        recommendations: list[str] = []
        if scanner_id == "nuclei" and not has_templates:
            recommendations.append("Run 'nuclei -update-templates' to download the template database")
        if scanner_id == "trivy":
            recommendations.append("Download the vulnerability DB with 'trivy image --download-db-only'")
        if scanner_id == "nikto" and not has_perl:
            recommendations.append("Install Perl (required: https://www.perl.org/get.html)")
        if scanner_id == "zap" and not has_java:
            recommendations.append("Install Java 11+ (required: https://adoptium.net)")
        if scanner_id in ("ffuf", "gobuster") and not has_wordlists:
            recommendations.append(
                f"Configure KINGSEC_{scanner_id.upper()}__WORDLIST to a real wordlist file, "
                "e.g. one from https://github.com/danielmiessler/SecLists"
            )
        if not permissions_ok:
            recommendations.append(f"Ensure {binary!r} has execute permissions")

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
            permissions_ok=permissions_ok,
            recommendations=tuple(recommendations),
            has_templates=has_templates,
            has_perl=has_perl,
            has_java=has_java,
            has_wordlists=has_wordlists,
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
