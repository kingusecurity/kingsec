"""``kingsec doctor`` — read-only scanner preflight check.

Usage::

    kingsec doctor
    kingsec doctor --profile web-scan
    python -m kingsec._doctor

For each of the six wired scanners (nmap, nuclei, nikto, ffuf, gobuster,
zap — semgrep/trivy/amass are unwired, out of scope here, see
docs/STATUS.md's Phase 2B roadmap item), reports: whether the binary is
found (and where, and its version), whether its required assets are
present, which target types it can serve, and — if unusable — the exact
command or config setting that fixes it.

Read-only by design: never installs, downloads, or writes anything. Does
not require a database to exist yet — deliberately does not call
``create_wired_application()`` (which builds a database engine),
because this command's whole purpose is helping a fresh install reach a
working state, which includes states before the database has been set
up. Loads Settings and registers only the scanner plugins, nothing else.

Derives every verdict from the SAME ``ScannerDiscoveryService`` and
``ScannerPluginRegistry`` the real ``ExecutionPlanner`` decides with
(via ``bootstrap.composition.build_execution_planner()``) — never a
second, independently-derived check. See that function's own docstring
for why this matters: two independently-maintained "is this scanner
usable" implementations disagreeing was the Run #4 reference-case root
cause this whole codebase already lived through once.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, TextIO

from kingsec import __version__
from kingsec.bootstrap.container import Container
from kingsec.domain import ScannerId, TargetType
from kingsec.infrastructure.config import load_settings
from kingsec.infrastructure.scanner import register_scanner

if TYPE_CHECKING:
    from kingsec.application.assessment_profiles import ExecutionPlanner
    from kingsec.application.scanner_discovery import ScannerStatus

# The six wired scanners (Phase 2B Task 1 Decisions 1/2 — the honest
# network scanner count). semgrep/trivy/amass are registered plugins but
# unwired from every profile; reporting on them here would contradict
# that decision, so they are deliberately excluded.
WIRED_SCANNERS: tuple[str, ...] = ("nmap", "nuclei", "nikto", "ffuf", "gobuster", "zap")

# "the default profile" (task 3a's exit-code gate): full-assessment is
# the profile that runs every wired scanner — no profile is literally
# named "default", and this is the one whose scope matches doctor's own
# ("for each of the six wired scanners") exactly.
DEFAULT_PROFILE_ID = "full-assessment"


def build_planner(env_file: str | None = None) -> ExecutionPlanner:
    """Load Settings and build an ExecutionPlanner without touching a database.

    Deliberately does not call ``create_wired_application()`` — that also
    builds a database engine (and, with ``ensure_directories=True``, can
    create the data directory), which this read-only command must never
    do. ``register_scanner()`` alone has no database dependency.
    """
    settings = load_settings(env_file)
    container = Container()
    register_scanner(container, settings)

    from kingsec.bootstrap.composition import build_execution_planner

    return build_execution_planner(container, settings)


def _target_types_served(planner: ExecutionPlanner, scanner_id: str) -> tuple[TargetType, ...]:
    """Every TargetType this scanner is compatible with, per the SAME
    registry.is_compatible() the real planner/orchestrator use."""
    registry = planner.registry
    if registry is None:
        return ()
    return tuple(t for t in TargetType if registry.is_compatible(ScannerId(scanner_id), t))


def _status_label(status: ScannerStatus) -> str:
    if not status.installed:
        return "NOT FOUND"
    if status.usable:
        return "OK"
    return "UNUSABLE"


def _format_scanner_block(status: ScannerStatus, target_types: tuple[TargetType, ...]) -> list[str]:
    label = _status_label(status)
    version_suffix = f" v{status.version}" if status.version else ""
    lines = [f"[{label:9}] {status.scanner_id:9} ({status.name}){version_suffix}"]

    if status.installed:
        lines.append(f"            binary:        {status.executable_path}")
    else:
        lines.append("            binary:        not found on PATH or common install locations")

    types_display = ", ".join(t.value for t in target_types) if target_types else "(none)"
    lines.append(f"            target types:  {types_display}")

    lines.append(f"            status:        {'usable' if status.usable else 'NOT usable'}")
    if status.availability_reason:
        lines.append(f"            reason:        {status.availability_reason}")
    if not status.usable:
        if status.install_hints:
            for hint in status.install_hints:
                lines.append(f"            fix:           {hint}")
        else:
            lines.append("            fix:           (no fix available - see reason above)")

    return lines


def _run(planner: ExecutionPlanner, profile_id: str, stream: TextIO) -> int:
    statuses = {s.scanner_id: s for s in planner.discovery.get_all_statuses()}

    profile = planner.get_profile(profile_id)
    profile_scanner_ids = set(profile.scanners) if profile is not None else set()

    lines: list[str] = [
        "KingSec Doctor - scanner preflight check",
        "=" * 42,
        "",
    ]

    usable_count = 0
    unusable_in_profile: list[str] = []

    for scanner_id in WIRED_SCANNERS:
        status = statuses.get(scanner_id)
        if status is None:
            # Cannot happen for a name in WIRED_SCANNERS against the real
            # manifest, but ScannerDiscoveryService.get_scanner_status()
            # itself is total (returns an "unknown scanner" status rather
            # than raising) — mirror that defensiveness here rather than
            # assume the dict lookup always hits.
            lines.append(f"[UNKNOWN  ] {scanner_id} - not in the scanner discovery manifest")
            lines.append("")
            if scanner_id in profile_scanner_ids:
                unusable_in_profile.append(scanner_id)
            continue

        target_types = _target_types_served(planner, scanner_id)
        lines.extend(_format_scanner_block(status, target_types))
        lines.append("")

        if status.usable:
            usable_count += 1
        elif scanner_id in profile_scanner_ids:
            unusable_in_profile.append(scanner_id)

    lines.append("-" * 42)
    lines.append(f"{len(WIRED_SCANNERS)} scanners checked: {usable_count} usable, {len(WIRED_SCANNERS) - usable_count} not usable")
    if profile is not None:
        lines.append(f"Default profile {profile_id!r} scanners: {', '.join(profile.scanners)}")
        if unusable_in_profile:
            lines.append(f"  UNUSABLE in this profile: {', '.join(unusable_in_profile)}")
        else:
            lines.append("  All scanners in this profile are usable.")
    else:
        lines.append(f"WARNING: profile {profile_id!r} does not exist - cannot evaluate the exit-code gate.")
        unusable_in_profile = list(WIRED_SCANNERS)  # fail closed, not open

    exit_code = 1 if unusable_in_profile else 0
    lines.append(f"Exit code: {exit_code}")

    stream.write("\n".join(lines) + "\n")
    return exit_code


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kingsec doctor",
        description="Read-only preflight check: which scanners can actually run, and how to fix the ones that can't.",
    )
    parser.add_argument("--version", action="version", version=f"kingsec {__version__}")
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE_ID,
        help=f"Profile whose scanners gate the exit code (default: {DEFAULT_PROFILE_ID!r})",
    )
    parser.add_argument(
        "--env-file",
        default=None,
        help="Optional .env path to load settings from (same as the server's own config loading)",
    )
    return parser.parse_args(argv)


def run_doctor(*, profile_id: str = DEFAULT_PROFILE_ID, env_file: str | None = None, stream: TextIO = sys.stdout) -> int:
    """Build the planner and run the preflight check — the public entry
    point ``kingsec.__main__`` (the `kingsec doctor` subcommand) calls."""
    planner = build_planner(env_file)
    return _run(planner, profile_id, stream)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return run_doctor(profile_id=args.profile, env_file=args.env_file, stream=sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
