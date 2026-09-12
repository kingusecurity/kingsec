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

import pytest

from kingsec.application.scanner_discovery import AssetRequirement, ScannerDiscoveryService


@pytest.fixture
def _mock_nuclei_binary_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "kingsec.application.scanner_discovery._find_executable",
        lambda binary: "/usr/local/bin/nuclei" if binary == "nuclei" else None,
    )
    monkeypatch.setattr(
        "kingsec.application.scanner_discovery._get_version",
        lambda *args, **kwargs: "3.0.0",
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
