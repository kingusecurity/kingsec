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
import subprocess  # nosec B404 -- see _probe_version()/_check_java() for the justification
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

# Task 3 Addition 1: a named file, not just "go get a wordlist from this
# 3.6GB repository" — Discovery/Web-Content/common.txt is SecLists' own
# conventional choice for web content discovery (ffuf/gobuster's actual
# use case): small (a few thousand common paths/filenames, not the full
# collection), MIT-licensed (see docs/LICENSING-RISK.md), and the file
# this project's own licence spot-check actually inspected. The default
# path is KingSec's own established home-directory convention
# (~/.kingsec, already used for its data directory) rather than
# reinventing one — "somewhere obvious to put it," not a guess.
_WORDLIST_FILENAME = "common.txt"
_WORDLIST_SOURCE_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
)


def _default_wordlist_path() -> Path:
    return Path.home() / ".kingsec" / "wordlists" / _WORDLIST_FILENAME


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
        # Task 5 Addition 3: the chocolatey 'zap' package is a .bat shim
        # that resolves via shutil.which() (PATHEXT-aware) but cannot be
        # executed by the scan path's raw CreateProcess (shell=False) -
        # not a bug in KingSec, a Windows CreateProcess limitation with no
        # fix that doesn't reintroduce a shell. Install ZAP via the
        # official installer and point KINGSEC_ZAP__BINARY_PATH at the
        # real ZAP.exe it installs - see docs/INSTALL.md.
        "windows": (
            "Install ZAP via the official installer from https://www.zaproxy.org/download/ "
            "(the chocolatey package's .bat shim will NOT work - see docs/INSTALL.md), then: "
            '$env:KINGSEC_ZAP__BINARY_PATH = "C:\\Program Files\\ZAP\\Zed Attack Proxy\\ZAP.exe"'
        ),
        "linux": "docker run -d --name zap ghcr.io/zaproxy/zaproxy:stable  (or  apt install zaproxy)",
    },
}

_SCANNER_MANIFEST: dict[str, dict[str, Any]] = {
    "nmap": {
        "name": "Nmap",
        "binary": "nmap",
        "version_args": ("--version",),
        "version_regex": r"version\s+(\d+(?:\.\d+)*)",
        "assets": [],
        "extra_checks": {
            "required_permissions": True,
        },
    },
    "nuclei": {
        "name": "Nuclei",
        "binary": "nuclei",
        "version_args": ("-version",),
        "version_regex": r"(\d+(?:\.\d+)*)",
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
        "version_regex": r"(\d+(?:\.\d+)*)",
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
        # Task 5 Addition 4: ffuf has no --version/-version flag at all
        # (verified against the real 2.2.1 binary on this host: it exits 2
        # with "flag provided but not defined: -version" for either
        # spelling) - a pre-existing latent defect that Addition 2's new
        # "must actually execute" usable-gate turned into a real, active
        # regression (ffuf works fine for real scans but was newly
        # reported NOT usable). Its version is only ever printed as the
        # first line of `-h`'s help output ("Fuzz Faster U Fool -
        # v2.2.1"), which always exits 0.
        "version_args": ("-h",),
        "version_regex": r"(\d+(?:\.\d+)*)",
        # Phase 2A Correction 4: path is None here deliberately — the real
        # path comes from the operator-configured FfufSettings.wordlist at
        # request time (see get_scanner_status()'s wordlist substitution
        # below), never this hardcoded Linux default. A missing wordlist
        # is now a real, required asset (optional=False) matching Nuclei's
        # templates requirement, not a silently-ignored one. install_hint
        # below is a placeholder — always overridden by
        # get_scanner_status() with _wordlist_setup_command()'s
        # platform-aware, pasteable command (Task 3 Addition 1).
        "assets": [
            AssetRequirement(
                name="Wordlist file",
                kind="file",
                path=None,
                install_hint="(overridden at runtime — see _wordlist_setup_command())",
            ),
        ],
        "extra_checks": {},
    },
    "gobuster": {
        "name": "Gobuster",
        "binary": "gobuster",
        "version_args": ("--version",),
        "version_regex": r"(\d+(?:\.\d+)*)",
        # Same as ffuf above: real path substituted from
        # GobusterSettings.wordlist at request time.
        "assets": [
            AssetRequirement(
                name="Wordlist file",
                kind="file",
                path=None,
                install_hint="(overridden at runtime — see _wordlist_setup_command())",
            ),
        ],
        "extra_checks": {},
    },
    "trivy": {
        "name": "Trivy",
        "binary": "trivy",
        "version_args": ("--version",),
        "version_regex": r"Version:\s*(\d+(?:\.\d+)*)",
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
        "version_regex": r"(\d+(?:\.\d+)*)",
        "assets": [],
        "extra_checks": {},
    },
    "amass": {
        "name": "Amass",
        "binary": "amass",
        "version_args": ("--version",),
        "version_regex": r"(\d+(?:\.\d+)*)",
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
        "version_regex": r"(\d+(?:\.\d+)*)",
        # Task 5: verified empirically against the real ZAP.exe on this
        # host - "-version" is not a lightweight flag, it boots the whole
        # platform before printing and exiting (~20s cold). The other 8
        # scanners' probes are near-instant and use the 15s default.
        "version_timeout": 45.0,
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


def _wordlist_setup_command(env_var: str) -> str:
    """One pasteable command (per this machine's real platform) that
    downloads the recommended wordlist to the conventional default path
    and points *env_var* at it. Task 3 Addition 1: doctor must give an
    operator something they can paste and run, not a research pointer.
    """
    target = _default_wordlist_path()
    if _current_platform() == "windows":
        return (
            f'New-Item -ItemType Directory -Force -Path "{target.parent}" | Out-Null; '
            f'Invoke-WebRequest -Uri "{_WORDLIST_SOURCE_URL}" -OutFile "{target}"; '
            f'$env:{env_var} = "{target}"'
        )
    return f'mkdir -p "{target.parent}" && curl -sSL -o "{target}" {_WORDLIST_SOURCE_URL} && export {env_var}="{target}"'


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def find_executable(binary: str) -> str | None:
    """Locate a binary using ``shutil.which`` with platform-specific PATH.

    Public (not `_`-prefixed) and the ONE resolution function for a
    configured binary value (Task 5 Addition 2): both ``get_scanner_status()``
    below and the ZAP scan adapter (``infrastructure/scanner/zap.py``) call
    this, instead of each independently calling ``shutil.which()``. That
    matters because ``shutil.which()`` is PATHEXT-aware (it will resolve a
    bare name to a ``.BAT``/``.CMD`` shim), while the real scan path invokes
    the resolved path via raw ``CreateProcess`` (``subprocess.run(...,
    shell=False)``), which is NOT PATHEXT-aware for ``.BAT``/``.CMD`` — a
    binary this function resolves can still fail to execute. That gap is
    exactly what ``_probe_version()`` below exists to catch, not something
    this function can paper over by resolving differently.

    ``binary`` may be a bare name (searched on PATH) or an operator-supplied
    absolute path (e.g. ``KINGSEC_ZAP__BINARY_PATH``) — ``shutil.which()``
    returns an absolute-path argument unchanged if it exists and is
    executable, without a PATH search.

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


@dataclass(frozen=True, slots=True)
class VersionProbe:
    """Result of actually invoking a scanner's version-probe command.

    Task 5 Addition 1 + 2: a single subprocess call now answers two
    previously-conflated questions at once, instead of doctor inferring
    "usable" purely from asset presence while ``_get_version`` silently
    swallowed every failure into ``None``:

    * ``executed`` — did the binary actually run and exit 0? ``False``
      covers both "couldn't be launched at all" (OSError/timeout - e.g. a
      Windows ``.bat`` resolved via PATHEXT that raw ``CreateProcess``
      can't execute) and "launched but exited non-zero" (e.g. the ZAP
      chocolatey shim's "The input line is too long." failure). Either
      way this is the Addition 2 "located but not executable" state, and
      it must never be read as version-parseable text.
    * ``version`` — only ever set when ``executed`` is True. A scanner
      that runs fine but whose ``--version`` output doesn't match
      ``version_regex`` is still a working scanner (``executed=True,
      version=None``), which is a different, non-blocking case from
      ``executed=False``.
    """

    executed: bool
    version: str | None
    error: str | None


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _strip_ansi(text: str) -> str:
    """Strip ANSI colour/cursor escape codes before version-regex matching.

    Found via real testing (Task 5 Addition 4): nuclei colours its
    ``-version`` output (``\\x1b[34mINF\\x1b[0m] ... Version: v3.11.1``),
    and the digits INSIDE the escape code itself (``34``) matched before
    the real version on this host, parsing as ``v34`` instead of
    ``v3.11.1`` — a successful invocation silently yielding a plausible
    but wrong version, adjacent to (not the same as) Addition 1's
    failure-as-success bug, and equally a "looks fine, isn't" defect.
    """
    return _ANSI_ESCAPE_RE.sub("", text)


def _probe_version(
    path: str,
    args: tuple[str, ...],
    regex: str,
    *,
    timeout: float = 15.0,
    cwd: str | None = None,
) -> VersionProbe:
    """Safely run ``<path> <args>`` and report whether it executed and its version.

    Uses ``subprocess.run`` with ``shell=False`` (list-based invocation),
    a timeout, and captures combined stdout+stderr.

    Addition 1: a non-zero exit (or a failed invocation) NEVER yields a
    parsed version — the old ``[\\d.]+`` regex matched the bare period in
    "The input line is too long." (the ZAP chocolatey shim's real failure
    text), turning a total invocation failure into an apparent version
    string ("v."). ``version_regex`` is now required to contain at least
    one digit AND extraction is only even attempted once ``returncode``
    has already been confirmed to be 0.

    ``cwd`` and ``timeout`` exist for the SAME reason ``zap.py``'s real
    scan invocation needs them (Task 5): ``ZAP.exe`` (an install4j native
    launcher) resolves its bundled classpath relative to its OWN
    directory, and its ``-version`` probe genuinely takes ~20s (a real
    JVM cold-boot of the whole platform, not a lightweight flag) —
    verified empirically against the real binary on this host. Without
    ``cwd``, ZAP.exe's launcher fails to load its main class but STILL
    EXITS 0 in well under a second, a second instance of Addition 1's
    exact defect class one layer deeper than the regex (a genuine
    failure at the OS-exit-code layer, not just the text-parsing layer)
    — caught only by actually testing this probe against the real binary
    with the real fix applied, not by inspecting the code.
    """
    try:
        # path is a filesystem path resolved by find_executable() via a
        # fixed search over well-known install locations for a hardcoded
        # binary name (from _SCANNER_MANIFEST, a static dict literal - see
        # line 119) or an operator-configured binary_path; args is that
        # same manifest entry's hardcoded version_args tuple (e.g.
        # ("--version",)). Neither is ever derived from a scan target,
        # request body, or other caller-supplied value - scanner_id only
        # selects among the fixed manifest keys and cannot influence the
        # command vector itself.
        result = subprocess.run(  # nosec B603
            [path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=cwd,
        )
    except OSError as exc:
        return VersionProbe(executed=False, version=None, error=str(exc))
    except subprocess.TimeoutExpired:
        return VersionProbe(
            executed=False, version=None, error=f"version probe timed out after {timeout:.0f}s"
        )

    if result.returncode != 0:
        detail_source = (result.stderr or result.stdout or "").strip()
        detail = detail_source.splitlines()[0][:200] if detail_source else "no output"
        return VersionProbe(
            executed=False,
            version=None,
            error=f"exited with code {result.returncode}: {detail}",
        )

    combined = _strip_ansi((result.stdout or "") + "\n" + (result.stderr or ""))
    match = re.search(regex, combined, re.IGNORECASE)
    return VersionProbe(executed=True, version=match.group(1) if match else None, error=None)


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
        # reasoning as _probe_version() above: no caller-supplied value
        # reaches this command vector.
        result = subprocess.run(  # nosec B603
            [java, "-version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        combined = _strip_ansi((result.stdout or "") + "\n" + (result.stderr or ""))
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
    ``GobusterSettings.wordlist`` values. ``nuclei_templates_dir`` follows
    the same rule for the adapter's explicit ``-t`` path. Without these,
    discovery can report a scanner unusable while the real adapter has a
    valid configured asset, or usable while the configured path is broken.
    """

    def __init__(
        self,
        *,
        ffuf_wordlist: str = "",
        gobuster_wordlist: str = "",
        nuclei_templates_dir: Path | None = None,
        binary_paths: dict[str, str] | None = None,
    ) -> None:
        self._ffuf_wordlist = ffuf_wordlist
        self._gobuster_wordlist = gobuster_wordlist
        self._nuclei_templates_dir = nuclei_templates_dir
        # Task 5 Addition 2: the operator's actually-configured binary_path
        # per scanner (e.g. Settings.zap.binary_path), keyed by scanner_id.
        # Without this, doctor always resolved the manifest's hardcoded
        # bare name ("zap") regardless of what KINGSEC_ZAP__BINARY_PATH was
        # set to — a scan-path/doctor disconnect on top of the
        # shutil.which()-vs-CreateProcess one this whole addition exists to
        # close. Same Correction-4 pattern already used for
        # ffuf_wordlist/gobuster_wordlist above. Falls back to the
        # manifest's bare name when a scanner_id has no entry.
        self._binary_paths = binary_paths or {}

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
        binary: str = self._binary_paths.get(scanner_id) or manifest["binary"]
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
                    install_hint=_wordlist_setup_command("KINGSEC_FFUF__WORDLIST"),
                    optional=assets[0].optional,
                )
            ]
        elif scanner_id == "gobuster" and assets:
            assets = [
                AssetRequirement(
                    name=assets[0].name,
                    kind=assets[0].kind,
                    path=self._gobuster_wordlist or None,
                    install_hint=_wordlist_setup_command("KINGSEC_GOBUSTER__WORDLIST"),
                    optional=assets[0].optional,
                )
            ]
        elif scanner_id == "nuclei" and self._nuclei_templates_dir is not None:
            # A configured -t path overrides Nuclei's default. Checking
            # ~/nuclei-templates instead could select a broken scan or
            # reject a valid one, so inspect the path the adapter uses.
            assets = [
                AssetRequirement(
                    name=asset.name,
                    kind=asset.kind,
                    path=(
                        str(self._nuclei_templates_dir)
                        if asset.name == "Nuclei templates"
                        else asset.path
                    ),
                    install_hint=asset.install_hint,
                    optional=asset.optional,
                )
                for asset in assets
            ]

        path = find_executable(binary)
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

        probe = _probe_version(
            path,
            version_args,
            version_regex,
            timeout=manifest.get("version_timeout", 15.0),
            # Same reason zap.py's real scan invocation sets cwd (Task 5):
            # a binary that resolves its own bundled resources relative to
            # its OWN directory (e.g. ZAP.exe) needs that as cwd to even
            # load correctly - harmless for the other 8 scanners, which
            # don't care what their cwd is.
            cwd=str(Path(path).parent),
        )
        version = probe.version

        warnings: list[str] = []
        missing_assets: list[str] = []
        for asset in assets:
            if not _check_asset(asset):
                missing_assets.append(asset.name)
                if not asset.optional:
                    # Short prose here - the actionable fix (which can now
                    # be a full pasteable command, Task 3 Addition 1) lives
                    # in install_hints/recommendations, not embedded in
                    # this one-line reason sentence.
                    warnings.append(f"Missing {asset.name}")

        # Task 5 Addition 2: a scanner is only usable if it actually
        # executed (probe.executed) — asset presence alone is no longer
        # sufficient. "Located via find_executable() but couldn't be run"
        # (e.g. a Windows .bat/.cmd resolved via PATHEXT that raw
        # CreateProcess can't execute) is a distinct, always-blocking
        # state, reported below with a reason naming the execution
        # failure specifically — never conflated with a missing-asset
        # warning.
        usable = probe.executed and (
            len(missing_assets) == 0
            or all(a.optional for a in assets if a.name in missing_assets)
        )

        all_asset_names = tuple(a.name for a in assets if not a.optional)
        missing_names = tuple(missing_assets)
        # This branch is only reached once the binary itself has already
        # been found (the `path is None` case above returns its own,
        # binary-only hint separately) — the platform "how to install the
        # binary" hint has no place here; the real fix at this point is
        # always about a missing ASSET, never the binary. Only REQUIRED
        # (non-optional) missing assets actually block `usable`, so only
        # those get a fix hint here — an optional asset's hint would tell
        # the operator to fix something that was never blocking anything.
        # Deduplicated (preserving order) since two assets can legitimately
        # share the same install command (e.g. nuclei's templates dir and
        # its optional config file both say "nuclei -update-templates").
        install_hints: list[str] = []
        for asset in assets:
            if (
                not asset.optional
                and asset.name in missing_assets
                and asset.install_hint
                and asset.install_hint not in install_hints
            ):
                install_hints.append(asset.install_hint)

        # Task 5 Addition 2/3: when the binary couldn't be executed at all,
        # an asset-missing hint would be misleading noise — the real fix is
        # about the BINARY, so surface the platform install/config hint
        # (Addition 3's KINGSEC_ZAP__BINARY_PATH guidance lives here for
        # zap) instead of whatever asset hints were collected above.
        execution_error_reason: str | None = None
        if not probe.executed:
            execution_error_reason = (
                f"{binary!r} was located at {path!r} but failed to execute: {probe.error}"
            )
            platform_hints = _INSTALL_HINTS.get(scanner_id, {})
            platform_hint = platform_hints.get(_current_platform(), "")
            install_hints = [platform_hint] if platform_hint else []

        extra = manifest.get("extra_checks", {})

        permissions_ok = _check_permissions(path)

        # Derive this convenience flag from the SAME asset decision above.
        # Re-checking ~/nuclei-templates here would reintroduce drift for an
        # explicitly configured -t path and could add a false setup
        # recommendation even while status.usable is True.
        has_templates = (
            "Nuclei templates" not in missing_assets
            if scanner_id == "nuclei"
            else False
        )
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
            availability_reason=(
                execution_error_reason
                if not probe.executed
                else (None if usable else "; ".join(warnings) or None)
            ),
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
