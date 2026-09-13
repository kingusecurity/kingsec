"""ScannerDiscoveryService.get_scanner_status() — install_hints correctness.

Regression test for a bug found while building `kingsec doctor` (Task
3a) and reproduced against this real host: `install_hints` always
included the "how to install the binary" hint even when the binary was
already found, and could duplicate an asset's install hint or include
one for an OPTIONAL (non-blocking) missing asset — producing a
misleading "download nuclei from..." fix for a scanner whose binary was
already present and usable, alongside real duplicate/extraneous hints.
Fixed in scanner_discovery.py: once the binary is found, install_hints
is built only from REQUIRED, actually-missing assets, deduplicated.
"""

from __future__ import annotations

import sys

import pytest

from kingsec.application.scanner_discovery import (
    AssetRequirement,
    ScannerDiscoveryService,
    VersionProbe,
    _probe_version,
)


@pytest.fixture
def _mock_nuclei_binary_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "kingsec.application.scanner_discovery.find_executable",
        lambda binary: "/usr/local/bin/nuclei" if binary == "nuclei" else None,
    )
    monkeypatch.setattr(
        "kingsec.application.scanner_discovery._probe_version",
        lambda *args, **kwargs: VersionProbe(executed=True, version="3.0.0", error=None),
    )
    monkeypatch.setattr(
        "kingsec.application.scanner_discovery._check_permissions",
        lambda path: True,
    )


class TestInstallHintsWhenBinaryIsAlreadyFound:
    def test_no_binary_download_hint_once_the_binary_is_found(
        self, _mock_nuclei_binary_found: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """nuclei's binary is found but its required templates dir is
        missing (the exact real-world shape reproduced on this host) -
        the fix must be about the missing asset, never "go download
        nuclei" — the binary is right there."""
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery._check_asset",
            lambda asset: False,  # both nuclei assets "missing"
        )
        status = ScannerDiscoveryService().get_scanner_status("nuclei")

        assert status.installed is True
        assert status.usable is False
        assert status.install_hints == ("nuclei -update-templates",)
        for hint in status.install_hints:
            assert "Download" not in hint
            assert "go install" not in hint

    def test_optional_missing_asset_contributes_no_fix_hint(
        self, _mock_nuclei_binary_found: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """nuclei's second asset (its template config file) is optional -
        it must never appear in install_hints or count toward usable,
        regardless of whether it's present."""

        def _check(asset: AssetRequirement) -> bool:
            # Only the required "Nuclei templates" directory is present;
            # the optional config file is "missing" too, but must not
            # affect usable or contribute a hint.
            return asset.name == "Nuclei templates"

        monkeypatch.setattr("kingsec.application.scanner_discovery._check_asset", _check)
        status = ScannerDiscoveryService().get_scanner_status("nuclei")

        assert status.usable is True
        assert status.install_hints == ()

    def test_no_duplicate_hints_when_two_required_assets_share_a_command(
        self, _mock_nuclei_binary_found: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two required assets that happen to share the same fix command
        must produce that command once in install_hints, not twice."""
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery._check_asset",
            lambda asset: False,
        )
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery._SCANNER_MANIFEST",
            {
                "nuclei": {
                    "name": "Nuclei",
                    "binary": "nuclei",
                    "version_args": ("-version",),
                    "version_regex": r"([\d.]+)",
                    "assets": [
                        AssetRequirement(name="Asset A", kind="directory", path="/a", install_hint="shared-fix-command"),
                        AssetRequirement(name="Asset B", kind="directory", path="/b", install_hint="shared-fix-command"),
                    ],
                    "extra_checks": {},
                }
            },
        )
        status = ScannerDiscoveryService().get_scanner_status("nuclei")

        assert status.install_hints == ("shared-fix-command",)


class TestVersionProbeNeverParsesAFailureAsSuccess:
    """Task 5 Addition 1: the recurring defect class ("nothing found" vs.
    "nothing looked"), instance six, inverted - a total invocation
    FAILURE rendering as an apparent SUCCESS. The old regex `[\\d.]+`
    matched the bare period in "The input line is too long." (the real
    text ZAP's chocolatey .bat shim produces on this host when invoked
    via raw CreateProcess), turning a failed invocation into a parsed
    version string ("."). Tightened to `\\d+(?:\\.\\d+)*` (at least one
    digit) AND gated on returncode == 0 so extraction is never even
    attempted against a failed invocation's output, regardless of content.
    """

    def test_nonzero_exit_with_bare_period_in_stderr_yields_no_version(self, tmp_path) -> None:
        script = tmp_path / "fake_scanner_too_long.py"
        script.write_text("import sys\nsys.stderr.write('The input line is too long.\\n')\nsys.exit(1)\n")

        probe = _probe_version(sys.executable, (str(script),), r"(\d+(?:\.\d+)*)")

        assert probe.executed is False
        assert probe.version is None

    def test_nonzero_exit_never_yields_a_version_regardless_of_output_content(self, tmp_path) -> None:
        """Even when the failing invocation's output LOOKS like a real,
        parseable version string, a non-zero exit must still yield no
        version - the gate is on returncode, never on what the text
        happens to contain."""
        script = tmp_path / "fake_scanner_plausible.py"
        script.write_text("import sys\nsys.stdout.write('nuclei version 3.2.1\\n')\nsys.exit(2)\n")

        probe = _probe_version(sys.executable, (str(script),), r"(\d+(?:\.\d+)*)")

        assert probe.executed is False
        assert probe.version is None

    def test_ansi_color_codes_do_not_contaminate_the_matched_version(self, tmp_path) -> None:
        """Found via real testing against nuclei (Task 5 Addition 4):
        `-version`'s colored `[34mINF[0m] ... Version: v3.11.1` output has
        digits INSIDE the ANSI escape code itself ("34") that matched
        before the real version, parsing as "34" instead of "3.11.1" - a
        successful invocation silently yielding a plausible but wrong
        version. ANSI escapes must be stripped before matching."""
        script = tmp_path / "fake_scanner_colored.py"
        script.write_text(
            "import sys\n"
            "sys.stdout.write('\\x1b[34mINF\\x1b[0m] Nuclei Engine Version: v3.11.1\\n')\n"
            "sys.exit(0)\n"
        )

        probe = _probe_version(sys.executable, (str(script),), r"(\d+(?:\.\d+)*)")

        assert probe.executed is True
        assert probe.version == "3.11.1"

    def test_zero_exit_with_matching_digits_still_extracts_a_version(self, tmp_path) -> None:
        """Sanity check the flip side: the gate must not swallow real,
        successful version probes."""
        script = tmp_path / "fake_scanner_ok.py"
        script.write_text("import sys\nsys.stdout.write('nuclei version 3.2.1\\n')\nsys.exit(0)\n")

        probe = _probe_version(sys.executable, (str(script),), r"version\s+(\d+(?:\.\d+)*)")

        assert probe.executed is True
        assert probe.version == "3.2.1"


class TestExecutionVerification:
    """Task 5 Addition 2: doctor must verify a scanner actually EXECUTES,
    not just that resolution located it. A binary resolved via PATHEXT
    (e.g. a Windows .bat/.cmd shim `find_executable()`/`shutil.which()`
    can see) that raw CreateProcess (`subprocess.run(..., shell=False)`)
    cannot run is a distinct, always-blocking state - never folded into
    asset-missing logic, and never reported usable (doctor's [OK])."""

    def test_located_but_unexecutable_binary_is_not_usable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery.find_executable",
            lambda binary: r"C:\ProgramData\chocolatey\bin\zap.bat" if binary == "zap" else None,
        )
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery._probe_version",
            lambda *a, **k: VersionProbe(
                executed=False,
                version=None,
                error="exited with code 1: The input line is too long.",
            ),
        )
        monkeypatch.setattr("kingsec.application.scanner_discovery._check_asset", lambda asset: True)
        monkeypatch.setattr("kingsec.application.scanner_discovery._check_permissions", lambda path: True)
        monkeypatch.setattr("kingsec.application.scanner_discovery._check_java", lambda: True)

        status = ScannerDiscoveryService().get_scanner_status("zap")

        assert status.installed is True
        assert status.usable is False  # NOT usable, not [OK] - doctor derives its label from this
        assert status.version is None
        assert status.availability_reason is not None
        assert "failed to execute" in status.availability_reason
        assert "The input line is too long." in status.availability_reason

    def test_executed_binary_is_usable_regardless_of_the_new_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sanity check the flip side: a binary that DOES execute must not
        be penalized by the new executed-gate - usable still depends only
        on required assets once execution itself has succeeded."""
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery.find_executable",
            lambda binary: "/usr/local/bin/nmap" if binary == "nmap" else None,
        )
        monkeypatch.setattr(
            "kingsec.application.scanner_discovery._probe_version",
            lambda *a, **k: VersionProbe(executed=True, version="7.94", error=None),
        )
        monkeypatch.setattr("kingsec.application.scanner_discovery._check_permissions", lambda path: True)

        status = ScannerDiscoveryService().get_scanner_status("nmap")

        assert status.usable is True
        assert status.version == "7.94"


class TestBinaryPathsUseOperatorConfiguration:
    """Task 5 Addition 2: doctor must resolve the operator's actually
    configured binary_path (e.g. KINGSEC_ZAP__BINARY_PATH), not the
    manifest's hardcoded bare name - otherwise doctor's before/after
    verdict for a config fix never changes, because it never looked at
    the config."""

    def test_configured_binary_path_overrides_the_manifest_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def _fake_find(binary: str) -> str | None:
            seen.append(binary)
            return None

        monkeypatch.setattr("kingsec.application.scanner_discovery.find_executable", _fake_find)

        ScannerDiscoveryService(
            binary_paths={"zap": r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe"}
        ).get_scanner_status("zap")

        assert seen == [r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe"]

    def test_no_configured_override_falls_back_to_manifest_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def _fake_find(binary: str) -> str | None:
            seen.append(binary)
            return None

        monkeypatch.setattr("kingsec.application.scanner_discovery.find_executable", _fake_find)

        ScannerDiscoveryService().get_scanner_status("zap")

        assert seen == ["zap"]
