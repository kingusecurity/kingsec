"""kingsec doctor — exit-code gate and output rendering.

The doctor/planner AGREEMENT test lives in
tests/unit/application/test_phase2a_honest_coverage.py's
TestDoctorAgreesWithPlanner (it needs the real ScannerPluginRegistry and
the planner's own profile matrix). This file covers _doctor.py's own
rendering/exit-code logic in isolation with small local fakes.
"""

from __future__ import annotations

import io

from kingsec._doctor import WIRED_SCANNERS, _run
from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.scanner_discovery import ScannerStatus
from kingsec.domain import TargetType


class _FakeDiscovery:
    def __init__(self, statuses: dict[str, ScannerStatus]) -> None:
        self._statuses = statuses

    def get_all_statuses(self) -> list[ScannerStatus]:
        return list(self._statuses.values())


class _FakeRegistry:
    """Reports every scanner compatible with every target type — this
    file only tests _run()'s own exit-code/rendering logic, not real
    compatibility (that's TestDoctorAgreesWithPlanner's job)."""

    def is_compatible(self, scanner_id: object, target_type: TargetType) -> bool:
        return True


def _status(scanner_id: str, *, installed: bool, usable: bool, install_hints: tuple[str, ...] = ()) -> ScannerStatus:
    return ScannerStatus(
        scanner_id=scanner_id,
        name=scanner_id.title(),
        installed=installed,
        executable_path=f"/usr/bin/{scanner_id}" if installed else None,
        version="1.0" if installed else None,
        usable=usable,
        availability_reason=None if usable else "not usable",
        install_hints=install_hints,
    )


def _all_usable_statuses() -> dict[str, ScannerStatus]:
    return {sid: _status(sid, installed=True, usable=True) for sid in WIRED_SCANNERS}


class TestExitCode:
    def test_zero_when_every_default_profile_scanner_is_usable(self) -> None:
        planner = ExecutionPlanner(discovery=_FakeDiscovery(_all_usable_statuses()), registry=_FakeRegistry())
        stream = io.StringIO()

        exit_code = _run(planner, "full-assessment", stream)

        assert exit_code == 0
        assert "Exit code: 0" in stream.getvalue()

    def test_nonzero_when_any_default_profile_scanner_is_unusable(self) -> None:
        statuses = _all_usable_statuses()
        statuses["nikto"] = _status("nikto", installed=False, usable=False, install_hints=("apt install nikto",))
        planner = ExecutionPlanner(discovery=_FakeDiscovery(statuses), registry=_FakeRegistry())
        stream = io.StringIO()

        exit_code = _run(planner, "full-assessment", stream)

        assert exit_code == 1
        output = stream.getvalue()
        assert "Exit code: 1" in output
        assert "nikto" in output

    def test_unusable_scanner_outside_the_named_profile_does_not_fail_it(self) -> None:
        """quick-scan only requires nmap — nuclei being unusable must not
        gate quick-scan's exit code."""
        statuses = _all_usable_statuses()
        statuses["nuclei"] = _status("nuclei", installed=True, usable=False)
        planner = ExecutionPlanner(discovery=_FakeDiscovery(statuses), registry=_FakeRegistry())
        stream = io.StringIO()

        exit_code = _run(planner, "quick-scan", stream)

        assert exit_code == 0

    def test_fails_closed_for_an_unknown_profile(self) -> None:
        planner = ExecutionPlanner(discovery=_FakeDiscovery(_all_usable_statuses()), registry=_FakeRegistry())
        stream = io.StringIO()

        exit_code = _run(planner, "no-such-profile", stream)

        assert exit_code == 1


class TestOutputIsReadableWithoutSourceAccess:
    def test_unusable_scanner_shows_its_fix_command(self) -> None:
        statuses = _all_usable_statuses()
        statuses["gobuster"] = _status(
            "gobuster", installed=True, usable=False, install_hints=("Configure KINGSEC_GOBUSTER__WORDLIST",)
        )
        planner = ExecutionPlanner(discovery=_FakeDiscovery(statuses), registry=_FakeRegistry())
        stream = io.StringIO()

        _run(planner, "full-assessment", stream)

        output = stream.getvalue()
        assert "Configure KINGSEC_GOBUSTER__WORDLIST" in output

    def test_output_contains_only_plain_ascii(self) -> None:
        """This is printed to a real Windows console (cmd.exe's default
        codepage cannot render an em dash) — every line must stay ASCII."""
        planner = ExecutionPlanner(discovery=_FakeDiscovery(_all_usable_statuses()), registry=_FakeRegistry())
        stream = io.StringIO()

        _run(planner, "full-assessment", stream)

        assert stream.getvalue().isascii()
