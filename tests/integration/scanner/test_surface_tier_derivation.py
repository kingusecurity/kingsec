"""Derived-tier verification: every wired scanner's declared surface_tier
must match what its real adapter's _build_args() actually does.

Phase 4 (authorization scope enforcement), the user's explicit requirement
on approving the redesign: "the tier table must be DERIVED from each
scanner plugin's own capability declaration, never a hand-maintained
parallel table - with a required test over the REAL registry proving every
wired scanner's declared tier matches its real _build_args() behavior."
Blocking 1 arose in the first place BECAUSE nothing checked a hand-authored
tier assumption against a scanner's real invocation - this file is the
check that closes that gap, and TestDerivedTierCoverageIsComplete below
guards against it silently reopening for any new scanner wired in later.
"""

from __future__ import annotations

from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.bootstrap.container import Container
from kingsec.domain import ScannerId, ScannerSurfaceTier, Target, TargetType
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.scanner.provisioning import register_scanner

# A URL target with a distinctive, non-default port and a distinctive path -
# chosen so that both "is the port restricted?" and "is the path baked into
# the probe?" are unambiguous in the resulting argv.
_URL_TARGET = Target("https://example.com:9443/very/distinctive/path123", TargetType.URL)
_DISTINCTIVE_PATH = "/very/distinctive/path123"

# Flags that would restrict a HOST_PORT_ANY_PATH scanner's own crawl/probe
# to a sub-path - the tier's own docstring claim (scanner.py) is "none pass
# a path-restricting flag"; this is what that claim means, checked directly.
_PATH_RESTRICTING_FLAGS = frozenset(
    {
        "-path",
        "--path",
        "-scope-path",
        "--scope-path",
        "-include-path",
        "--include-path",
        "-exclude-paths",
        "--exclude-paths",
    }
)

# The scanners this file has a dedicated TestXDerivedTier class for below -
# every scanner a real assessment profile wires in must appear here (see
# TestDerivedTierCoverageIsComplete), or this suite has gone stale.
_TIER_VERIFIED_SCANNER_IDS = frozenset({"nmap", "nuclei", "nikto", "ffuf", "gobuster", "zap"})


def _real_registry() -> ScannerPluginRegistry:
    """The REAL scanner plugin registry, wired exactly as
    infrastructure.scanner.provisioning.register_scanner() does (same
    function, default Settings()) - never a stub. Matches the precedent in
    tests/unit/application/test_phase2a_honest_coverage.py's own
    _real_registry() helper, for the same reason: a tier check against a
    fabricated registry would prove nothing about the real adapters.
    """
    container = Container()
    register_scanner(container, Settings())
    return container.resolve(ScannerPluginRegistry)  # type: ignore[return-value]


def _declared_tier(registry: ScannerPluginRegistry, scanner_id: str) -> ScannerSurfaceTier:
    plugin = registry.get(ScannerId(scanner_id))
    tiers = {capability.surface_tier for capability in plugin.capabilities()}
    assert len(tiers) == 1, f"{scanner_id} declares more than one surface_tier across its capabilities: {tiers}"
    return next(iter(tiers))


def _wired_scanner_ids() -> frozenset[str]:
    """Every scanner id referenced by at least one real assessment profile -
    derived from ExecutionPlanner's own profile registry, never hand-typed
    (the same "never a hand-maintained parallel table" principle this
    whole file exists to enforce, applied to the test suite itself)."""
    planner = ExecutionPlanner()
    ids: set[str] = set()
    for profile in planner.list_profiles():
        ids.update(profile.scanners)
    return frozenset(ids)


# ---------------------------------------------------------------------------
# nmap - HOST_ANY_PORT
# ---------------------------------------------------------------------------


class TestNmapDerivedTier:
    def test_declared_tier_is_host_any_port(self) -> None:
        registry = _real_registry()
        assert _declared_tier(registry, "nmap") == ScannerSurfaceTier.HOST_ANY_PORT

    def test_sweep_invocation_has_no_port_restriction(self) -> None:
        """The real HOST_ANY_PORT claim: nmap's sweep invocation
        (port_spec=None) never restricts to the target's own port."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("nmap"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_single_invocation_args(_URL_TARGET, "example.com", False, port_spec=None)
        assert "-p" not in args

    def test_explicit_invocation_does_restrict_to_the_targets_port(self) -> None:
        """The paired half of the two-invocation design: nmap also runs a
        port-restricted invocation - the sweep is not the only one, it is
        the one that makes the declared tier HOST_ANY_PORT rather than
        HOST_PORT_ANY_PATH."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("nmap"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_single_invocation_args(_URL_TARGET, "example.com", False, port_spec="9443")
        assert "-p" in args
        assert "9443" in args


# ---------------------------------------------------------------------------
# nikto - HOST_PORT_ANY_PATH
# ---------------------------------------------------------------------------


class TestNiktoDerivedTier:
    def test_declared_tier_is_host_port_any_path(self) -> None:
        registry = _real_registry()
        assert _declared_tier(registry, "nikto") == ScannerSurfaceTier.HOST_PORT_ANY_PATH

    def test_built_args_drop_the_targets_path_entirely(self) -> None:
        """Nikto's own target parsing extracts host/port only - the path
        is never passed to the binary at all, the strongest possible
        proof of "any path"."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("nikto"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_args(_URL_TARGET)
        assert not any(_DISTINCTIVE_PATH in arg for arg in args)

    def test_built_args_carry_no_path_restricting_flag(self) -> None:
        registry = _real_registry()
        adapter = registry.get(ScannerId("nikto"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_args(_URL_TARGET)
        assert not (_PATH_RESTRICTING_FLAGS & set(args))


# ---------------------------------------------------------------------------
# nuclei - HOST_PORT_ANY_PATH
# ---------------------------------------------------------------------------


class TestNucleiDerivedTier:
    def test_declared_tier_is_host_port_any_path(self) -> None:
        registry = _real_registry()
        assert _declared_tier(registry, "nuclei") == ScannerSurfaceTier.HOST_PORT_ANY_PATH

    def test_built_args_carry_no_path_restricting_flag(self) -> None:
        """Nuclei is handed the full target URL (path included) via -u,
        but never a flag that would RESTRICT its own template probing to
        that path - the tier's real claim, verified directly against
        nuclei.py's _build_args()."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("nuclei"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_args(_URL_TARGET)
        assert not (_PATH_RESTRICTING_FLAGS & set(args))


# ---------------------------------------------------------------------------
# zap - HOST_PORT_ANY_PATH
# ---------------------------------------------------------------------------


class TestZapDerivedTier:
    def test_declared_tier_is_host_port_any_path(self) -> None:
        registry = _real_registry()
        assert _declared_tier(registry, "zap") == ScannerSurfaceTier.HOST_PORT_ANY_PATH

    def test_built_args_carry_no_path_restricting_flag(self) -> None:
        """ZAP's quick-scan mode spiders from the given URL (path
        included, via -quickurl) but takes no flag restricting that spider
        to the given path."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("zap"))._adapter  # type: ignore[attr-defined]
        args, _cwd, _output_path = adapter._build_args(_URL_TARGET)
        assert not (_PATH_RESTRICTING_FLAGS & set(args))


# ---------------------------------------------------------------------------
# ffuf - HOST_PORT_PATH
# ---------------------------------------------------------------------------


class TestFfufDerivedTier:
    def test_declared_tier_is_host_port_path(self) -> None:
        registry = _real_registry()
        assert _declared_tier(registry, "ffuf") == ScannerSurfaceTier.HOST_PORT_PATH

    def test_built_args_bake_the_targets_path_into_the_fuzz_base(self) -> None:
        """ffuf's -u argument is f"{base_url}/FUZZ" - the target's path is
        physically the prefix every fuzzed request is sent under, the
        mechanical proof this scanner respects path as a boundary."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("ffuf"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_args(_URL_TARGET)
        assert any(f"{_DISTINCTIVE_PATH}/FUZZ" in arg for arg in args)


# ---------------------------------------------------------------------------
# gobuster - HOST_PORT_PATH
# ---------------------------------------------------------------------------


class TestGobusterDerivedTier:
    def test_declared_tier_is_host_port_path(self) -> None:
        registry = _real_registry()
        assert _declared_tier(registry, "gobuster") == ScannerSurfaceTier.HOST_PORT_PATH

    def test_built_args_bake_the_targets_path_into_the_base_url(self) -> None:
        """Gobuster's dir mode passes the target's full URL (path
        included) as -u, and enumerates wordlist entries as children of
        that path - the mechanical proof this scanner respects path as a
        boundary."""
        registry = _real_registry()
        adapter = registry.get(ScannerId("gobuster"))._adapter  # type: ignore[attr-defined]
        args = adapter._build_args(_URL_TARGET)
        assert any(_DISTINCTIVE_PATH in arg for arg in args)


# ---------------------------------------------------------------------------
# Coverage: this suite itself must never go stale
# ---------------------------------------------------------------------------


class TestDerivedTierCoverageIsComplete:
    def test_every_wired_scanner_has_a_dedicated_derived_tier_test(self) -> None:
        """Guards against the exact failure mode this file exists to
        prevent: a new scanner gets wired into a real profile and nobody
        adds a test proving its declared surface_tier matches its real
        _build_args() behavior. If this fails, add a TestXDerivedTier
        class above for the scanner id it names."""
        wired = _wired_scanner_ids()
        untested = wired - _TIER_VERIFIED_SCANNER_IDS
        assert not untested, f"scanner(s) {untested} are wired into a real profile but have no derived-tier test"

    def test_every_registered_plugin_declares_a_valid_surface_tier(self) -> None:
        """Even unwired scanners (amass, semgrep, trivy) must declare
        SOME ScannerSurfaceTier - enforced structurally by
        ScannerCapability's required field, checked here against the real
        registry as a belt-and-braces regression guard."""
        registry = _real_registry()
        for metadata, _availability in registry.list_all():
            plugin = registry.get(metadata.id)
            for capability in plugin.capabilities():
                assert isinstance(capability.surface_tier, ScannerSurfaceTier)
