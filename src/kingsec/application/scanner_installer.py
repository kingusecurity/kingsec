"""Scanner Installer Service.

Application-layer service that detects the operating system, available package
managers, and provides safe installation commands for each scanner.

This service does NOT execute any commands. It only generates commands and
instructions that can be presented to the user or copied to the clipboard.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Literal

Platform = Literal["windows", "linux", "macos"]
PackageManager = Literal["chocolatey", "winget", "scoop", "apt", "dnf", "pacman", "brew", "pip", "go", "docker", "manual"]


@dataclass(frozen=True, slots=True)
class InstallCommand:
    """A safe installation command for a scanner on a specific platform."""

    manager: PackageManager
    command: str
    description: str
    requires_admin: bool = False
    requires_shell_restart: bool = False


@dataclass(frozen=True, slots=True)
class ScannerInstallGuide:
    """Complete installation guidance for one scanner on one platform."""

    scanner_id: str
    platform: Platform
    package_managers: tuple[InstallCommand, ...]
    verify_command: str
    uninstall_command: str | None = None
    website: str = ""
    min_version: str = ""
    known_issues: tuple[str, ...] = ()
    expected_binary: str = ""
    notes: str = ""


@dataclass(frozen=True, slots=True)
class PlatformInstallationGuide:
    """All installation guides for a single scanner across platforms."""

    scanner_id: str
    name: str
    windows: tuple[InstallCommand, ...] = ()
    linux: tuple[InstallCommand, ...] = ()
    macos: tuple[InstallCommand, ...] = ()
    verify_command: str = ""
    uninstall_command: str | None = None
    website: str = ""
    min_version: str = ""
    known_issues: tuple[str, ...] = ()
    expected_binary: str = ""
    notes: str = ""


# ---------------------------------------------------------------------------
# Platform utilities
# ---------------------------------------------------------------------------


def detect_platform() -> Platform:
    p = sys.platform
    if "win" in p:
        return "windows"
    if "linux" in p:
        return "linux"
    return "macos"


def detect_package_managers() -> tuple[PackageManager, ...]:
    """Detect which package managers are available on the current system.

    Uses ``shutil.which`` to check for common package manager binaries.
    Returns a tuple of available managers in priority order.
    """
    import shutil

    found: list[PackageManager] = []
    platform = detect_platform()

    if platform == "windows":
        if shutil.which("choco"):
            found.append("chocolatey")
        if shutil.which("winget"):
            found.append("winget")
        if shutil.which("scoop"):
            found.append("scoop")
        if shutil.which("pip"):
            found.append("pip")
        if shutil.which("go"):
            found.append("go")
        if not found:
            found.append("manual")

    elif platform == "linux":
        if shutil.which("apt-get") or shutil.which("apt"):
            found.append("apt")
        elif shutil.which("dnf"):
            found.append("dnf")
        elif shutil.which("pacman"):
            found.append("pacman")
        else:
            found.append("manual")
        if shutil.which("pip"):
            found.append("pip")
        if shutil.which("go"):
            found.append("go")
        if shutil.which("docker"):
            found.append("docker")

    elif platform == "macos":
        if shutil.which("brew"):
            found.append("brew")
        else:
            found.append("manual")
        if shutil.which("pip"):
            found.append("pip")
        if shutil.which("go"):
            found.append("go")
        if shutil.which("docker"):
            found.append("docker")

    return tuple(found)


# ---------------------------------------------------------------------------
# Scanner installation data
# ---------------------------------------------------------------------------


_SCANNER_INSTALL_GUIDES: dict[str, PlatformInstallationGuide] = {}


def _build_guides() -> None:
    """Build the complete installation guide database."""
    global _SCANNER_INSTALL_GUIDES

    _SCANNER_INSTALL_GUIDES = {
        "nmap": PlatformInstallationGuide(
            scanner_id="nmap",
            name="Nmap",
            windows=(
                InstallCommand("chocolatey", "choco install nmap", "Install via Chocolatey", requires_admin=True),
                InstallCommand("winget", "winget install Insecure.Nmap", "Install via WinGet"),
                InstallCommand("scoop", "scoop install nmap", "Install via Scoop"),
                InstallCommand("manual", "Download from https://nmap.org/download.html", "Download and run the installer"),
            ),
            linux=(
                InstallCommand("apt", "sudo apt-get install nmap", "Install via APT", requires_admin=True),
                InstallCommand("dnf", "sudo dnf install nmap", "Install via DNF", requires_admin=True),
                InstallCommand("pacman", "sudo pacman -S nmap", "Install via Pacman", requires_admin=True),
                InstallCommand("manual", "Download from https://nmap.org/download.html", "Build from source"),
            ),
            macos=(
                InstallCommand("brew", "brew install nmap", "Install via Homebrew"),
            ),
            verify_command="nmap --version",
            uninstall_command=None,
            website="https://nmap.org",
            min_version="7.90",
            expected_binary="nmap",
            known_issues=("On Linux, Nmap requires root privileges for SYN scans. Use sudo or set capabilities: sudo setcap cap_net_raw+ep $(which nmap)",),
            notes="Nmap is the most widely used port scanner. It is available on all major platforms and is typically the first scanner to install.",
        ),
        "nuclei": PlatformInstallationGuide(
            scanner_id="nuclei",
            name="Nuclei",
            windows=(
                InstallCommand("chocolatey", "choco install nuclei", "Install via Chocolatey", requires_admin=True),
                InstallCommand("winget", "winget install ProjectDiscovery.Nuclei", "Install via WinGet"),
                InstallCommand("scoop", "scoop install nuclei", "Install via Scoop"),
                InstallCommand("go", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/projectdiscovery/nuclei/releases", "Download the latest release binary"),
            ),
            linux=(
                InstallCommand("apt", "sudo apt-get install nuclei", "Install via APT (may not be in default repos)", requires_admin=True),
                InstallCommand("go", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/projectdiscovery/nuclei/releases", "Download the latest release binary"),
            ),
            macos=(
                InstallCommand("brew", "brew install nuclei", "Install via Homebrew"),
                InstallCommand("go", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "Install via Go"),
            ),
            verify_command="nuclei -version",
            uninstall_command=None,
            website="https://github.com/projectdiscovery/nuclei",
            min_version="3.0.0",
            expected_binary="nuclei",
            known_issues=(
                "Nuclei templates must be downloaded separately via 'nuclei -update-templates'",
                "The Go install method requires Go 1.20+ and adds to ~/go/bin which may not be in PATH",
            ),
            notes="After installing Nuclei, run 'nuclei -update-templates' to download the required template database.",
        ),
        "nikto": PlatformInstallationGuide(
            scanner_id="nikto",
            name="Nikto",
            windows=(
                InstallCommand("manual", "Download from https://github.com/sullo/nikto/releases", "Extract the ZIP archive and run nikto.pl with Perl"),
            ),
            linux=(
                InstallCommand("apt", "sudo apt-get install nikto", "Install via APT", requires_admin=True),
                InstallCommand("dnf", "sudo dnf install nikto", "Install via DNF", requires_admin=True),
                InstallCommand("manual", "Download from https://github.com/sullo/nikto/releases", "Clone the repository and run nikto.pl"),
            ),
            macos=(
                InstallCommand("brew", "brew install nikto", "Install via Homebrew"),
            ),
            verify_command="nikto -Version",
            uninstall_command=None,
            website="https://github.com/sullo/nikto",
            min_version="2.5.0",
            expected_binary="nikto",
            known_issues=("Nikto requires Perl to run (perl is typically pre-installed on Linux/macOS, required on Windows)",),
            notes="Nikto is a Perl-based web server scanner. On Windows, you need Perl installed (e.g., Strawberry Perl).",
        ),
        "ffuf": PlatformInstallationGuide(
            scanner_id="ffuf",
            name="FFUF",
            windows=(
                InstallCommand("chocolatey", "choco install ffuf", "Install via Chocolatey", requires_admin=True),
                InstallCommand("scoop", "scoop install ffuf", "Install via Scoop"),
                InstallCommand("go", "go install github.com/ffuf/ffuf/v2@latest", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/ffuf/ffuf/releases", "Download the latest release binary"),
            ),
            linux=(
                InstallCommand("go", "go install github.com/ffuf/ffuf/v2@latest", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/ffuf/ffuf/releases", "Download the latest release binary"),
            ),
            macos=(
                InstallCommand("brew", "brew install ffuf", "Install via Homebrew"),
                InstallCommand("go", "go install github.com/ffuf/ffuf/v2@latest", "Install via Go"),
            ),
            verify_command="ffuf --version",
            uninstall_command=None,
            website="https://github.com/ffuf/ffuf",
            min_version="2.0.0",
            expected_binary="ffuf",
            known_issues=(
                "FFUF requires wordlists for directory/content discovery. Common wordlists are at /usr/share/wordlists/ on Linux",
                "The Go install method adds to ~/go/bin which may not be in PATH",
            ),
            notes="FFUF is a fast web fuzzer. For best results, provide a wordlist (e.g., SecLists or common.txt).",
        ),
        "gobuster": PlatformInstallationGuide(
            scanner_id="gobuster",
            name="Gobuster",
            windows=(
                InstallCommand("chocolatey", "choco install gobuster", "Install via Chocolatey", requires_admin=True),
                InstallCommand("scoop", "scoop install gobuster", "Install via Scoop"),
                InstallCommand("go", "go install github.com/OJ/gobuster/v3@latest", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/OJ/gobuster/releases", "Download the latest release binary"),
            ),
            linux=(
                InstallCommand("go", "go install github.com/OJ/gobuster/v3@latest", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/OJ/gobuster/releases", "Download the latest release binary"),
            ),
            macos=(
                InstallCommand("brew", "brew install gobuster", "Install via Homebrew"),
                InstallCommand("go", "go install github.com/OJ/gobuster/v3@latest", "Install via Go"),
            ),
            verify_command="gobuster --version",
            uninstall_command=None,
            website="https://github.com/OJ/gobuster",
            min_version="3.0.0",
            expected_binary="gobuster",
            known_issues=(
                "Gobuster requires wordlists for directory/file discovery",
                "The Go install method adds to ~/go/bin which may not be in PATH",
            ),
            notes="Gobuster is a directory/file busting tool. Provide wordlists for effective scanning.",
        ),
        "trivy": PlatformInstallationGuide(
            scanner_id="trivy",
            name="Trivy",
            windows=(
                InstallCommand("chocolatey", "choco install trivy", "Install via Chocolatey", requires_admin=True),
                InstallCommand("winget", "winget install AquaSecurity.Trivy", "Install via WinGet"),
                InstallCommand("manual", "Download from https://github.com/aquasecurity/trivy/releases", "Download the Windows binary and add to PATH"),
            ),
            linux=(
                InstallCommand("apt", "sudo apt-get install trivy", "Install via APT (add repo first: see docs)", requires_admin=True),
                InstallCommand("manual", "Download from https://github.com/aquasecurity/trivy/releases", "Download the Linux binary"),
            ),
            macos=(
                InstallCommand("brew", "brew install trivy", "Install via Homebrew"),
            ),
            verify_command="trivy --version",
            uninstall_command=None,
            website="https://github.com/aquasecurity/trivy",
            min_version="0.45.0",
            expected_binary="trivy",
            known_issues=(
                "Trivy requires a vulnerability database download before first use: trivy image --download-db-only",
                "The vulnerability database is cached at ~/.cache/trivy/db/",
            ),
            notes="After installing Trivy, download the vulnerability database with 'trivy image --download-db-only'.",
        ),
        "semgrep": PlatformInstallationGuide(
            scanner_id="semgrep",
            name="Semgrep",
            windows=(
                InstallCommand("pip", "pip install semgrep", "Install via pip"),
                InstallCommand("manual", "Download from https://github.com/semgrep/semgrep/releases", "Download the Windows binary"),
            ),
            linux=(
                InstallCommand("pip", "pip install semgrep", "Install via pip"),
                InstallCommand("apt", "sudo apt-get install semgrep", "Install via APT", requires_admin=True),
                InstallCommand("manual", "Download from https://github.com/semgrep/semgrep/releases", "Download the Linux binary"),
            ),
            macos=(
                InstallCommand("brew", "brew install semgrep", "Install via Homebrew"),
                InstallCommand("pip", "pip install semgrep", "Install via pip"),
            ),
            verify_command="semgrep --version",
            uninstall_command=None,
            website="https://github.com/semgrep/semgrep",
            min_version="1.30.0",
            expected_binary="semgrep",
            known_issues=(),
            notes="Semgrep is a static analysis tool. It can also be run via Docker: docker run --rm -v $(pwd):/src semgrep/semgrep semgrep scan /src",
        ),
        "amass": PlatformInstallationGuide(
            scanner_id="amass",
            name="Amass",
            windows=(
                InstallCommand("chocolatey", "choco install amass", "Install via Chocolatey", requires_admin=True),
                InstallCommand("scoop", "scoop install amass", "Install via Scoop"),
                InstallCommand("go", "go install -v github.com/owasp-amass/amass/v4/...@master", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/owasp-amass/amass/releases", "Download the latest release binary"),
            ),
            linux=(
                InstallCommand("go", "go install -v github.com/owasp-amass/amass/v4/...@master", "Install via Go"),
                InstallCommand("manual", "Download from https://github.com/owasp-amass/amass/releases", "Download the latest release binary"),
            ),
            macos=(
                InstallCommand("brew", "brew install amass", "Install via Homebrew"),
                InstallCommand("go", "go install -v github.com/owasp-amass/amass/v4/...@master", "Install via Go"),
            ),
            verify_command="amass --version",
            uninstall_command=None,
            website="https://github.com/owasp-amass/amass",
            min_version="4.0.0",
            expected_binary="amass",
            known_issues=(
                "Amass may require API keys for maximum effectiveness (Shodan, Censys, etc.)",
                "The Go install method adds to ~/go/bin which may not be in PATH",
            ),
            notes="Amass performs subdomain enumeration. For best results, configure API keys in the Amass config file.",
        ),
        "zap": PlatformInstallationGuide(
            scanner_id="zap",
            name="OWASP ZAP",
            windows=(
                InstallCommand("manual", "Download from https://www.zaproxy.org/download/", "Download and run the Windows installer"),
                InstallCommand("chocolatey", "choco install zap", "Install via Chocolatey", requires_admin=True),
            ),
            linux=(
                InstallCommand("docker", "docker run -d --name zap ghcr.io/zaproxy/zaproxy:stable", "Run via Docker"),
                InstallCommand("apt", "sudo apt-get install zaproxy", "Install via APT", requires_admin=True),
                InstallCommand("manual", "Download from https://www.zaproxy.org/download/", "Download the Linux installer"),
            ),
            macos=(
                InstallCommand("brew", "brew install --cask zap", "Install via Homebrew Cask"),
                InstallCommand("docker", "docker run -d --name zap ghcr.io/zaproxy/zaproxy:stable", "Run via Docker"),
            ),
            verify_command="zap --version 2>/dev/null || echo 'Check ZAP installation manually'",
            uninstall_command=None,
            website="https://www.zaproxy.org",
            min_version="2.14.0",
            expected_binary="zap",
            known_issues=(
                "ZAP requires Java Runtime Environment (JRE) 11 or later",
                "Docker is the recommended way to run ZAP on Linux",
                "The ZAP binary may not be directly invocable on all platforms",
            ),
            notes="OWASP ZAP is a web application security scanner. Docker is the recommended installation method on Linux.",
        ),
    }


def get_install_guide(scanner_id: str) -> PlatformInstallationGuide | None:
    if not _SCANNER_INSTALL_GUIDES:
        _build_guides()
    return _SCANNER_INSTALL_GUIDES.get(scanner_id)


def get_all_guides() -> dict[str, PlatformInstallationGuide]:
    if not _SCANNER_INSTALL_GUIDES:
        _build_guides()
    return dict(_SCANNER_INSTALL_GUIDES)


def get_commands_for_current_platform(scanner_id: str) -> tuple[InstallCommand, ...]:
    """Get installation commands for a scanner on the current platform."""
    guide = get_install_guide(scanner_id)
    if guide is None:
        return ()
    platform = detect_platform()
    if platform == "windows":
        return guide.windows
    elif platform == "linux":
        return guide.linux
    else:
        # Platform is Literal["windows", "linux", "macos"] and
        # detect_platform() is exhaustive by construction (its own
        # unconditional trailing `return "macos"` means no fourth value is
        # ever possible) - mypy proves the "macos" case is the only one
        # left here, so a further elif + fallback return would be
        # unreachable dead code, not a missed case or a disabled check
        # (investigated and confirmed for Phase 12's mypy `unreachable`
        # finding at this file's former line 415).
        return guide.macos


def get_best_command(scanner_id: str) -> InstallCommand | None:
    """Get the best (highest priority) install command for a scanner on this system."""
    commands = get_commands_for_current_platform(scanner_id)
    if not commands:
        return None
    available = detect_package_managers()
    for cmd in commands:
        if cmd.manager in available or cmd.manager == "manual":
            return cmd
    return commands[0] if commands else None


class ScannerInstaller:
    """Provides safe installation commands for scanners.

    This service does NOT execute any commands. It only generates commands
    and guidance that can be presented to the user.
    """

    @staticmethod
    def detect_platform() -> Platform:
        return detect_platform()

    @staticmethod
    def detect_package_managers() -> tuple[PackageManager, ...]:
        return detect_package_managers()

    @staticmethod
    def get_install_command(scanner_id: str) -> InstallCommand | None:
        return get_best_command(scanner_id)

    @staticmethod
    def get_verify_command(scanner_id: str) -> str:
        guide = get_install_guide(scanner_id)
        if guide is None:
            return ""
        return guide.verify_command

    @staticmethod
    def get_all_commands(scanner_id: str) -> tuple[InstallCommand, ...]:
        return get_commands_for_current_platform(scanner_id)

    @staticmethod
    def get_guide(scanner_id: str) -> PlatformInstallationGuide | None:
        return get_install_guide(scanner_id)

    @staticmethod
    def get_install_summary(scanner_id: str) -> str:
        """Return a human-readable install summary for a scanner."""
        guide = get_install_guide(scanner_id)
        if guide is None:
            return f"No installation guide available for {scanner_id!r}"
        platform = detect_platform()
        lines = [f"=== {guide.name} ({guide.scanner_id}) ==="]
        lines.append(f"Website: {guide.website}")
        lines.append(f"Min version: {guide.min_version}")
        lines.append(f"Verify: {guide.verify_command}")
        lines.append(f"Platform: {platform}")
        lines.append("")
        commands = get_commands_for_current_platform(scanner_id)
        if commands:
            lines.append("Installation options:")
            for cmd in commands:
                admin = "[ADMIN]" if cmd.requires_admin else ""
                lines.append(f"  {admin} {cmd.manager:12s} {cmd.command}")
        lines.append("")
        if guide.known_issues:
            lines.append("Known issues:")
            for issue in guide.known_issues:
                lines.append(f"  - {issue}")
        return "\n".join(lines)
