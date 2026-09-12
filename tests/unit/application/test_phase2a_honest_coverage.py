"""Phase 2A: honest execution and coverage — regression tests.

Covers the specific requirements from the Phase 2A Step 2 acceptance
criteria:

    1. The reference-case regression test reproducing Run #4 (Phase 1
       E2E-EVIDENCE.md): a full-assessment run against an IP_ADDRESS
       target where 6 of 9 scanners never execute. Under the pre-Phase-2A
       code this produced ``AssessmentStatus.COMPLETED`` with no coverage
       warning anywhere ("88.0/100 — Sound"). This test asserts the fixed
       behavior: ``COMPLETED_WITH_GAPS`` and a verdict that names every
       non-running scanner.
    2. The planner/orchestrator invariant: a scanner the plan selected but
       the executor never brought to a terminal state must fail loudly.
    3. ``ExecutionPlanner.plan()`` always returns a decision for every
       scanner in the profile — never a partial list.
    4. Wordlist detection resolves correctly on a real Windows-style path
       (Correction 4).
    5. FIX 9: a job left RUNNING by a simulated crash resolves to a
       terminal status when the startup recovery pass runs.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest

from kingsec.application.assessment_execution import AssessmentExecutionEngine
from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.dto import SubmitAssessmentRequest
from kingsec.application.errors import AssessmentNotFoundError
from kingsec.application.ports import AssessmentRepository
from kingsec.application.ports.repositories import AssessmentPage
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.application.scanner_discovery import AssetRequirement, ScannerStatus, _check_asset
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.resolve_orphaned_assessments import ResolveOrphanedAssessments
from kingsec.bootstrap.container import Container
from kingsec.domain import Assessment, AssessmentId, Finding, Report, ScannerId, Target, TargetType
from kingsec.domain.authorization import Authorization
from kingsec.domain.enums import AssessmentStatus, ScannerRunState
from kingsec.domain.report import failed_scanners_in
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.reporting.templates import render_report_html
from kingsec.infrastructure.scanner.provisioning import register_scanner
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

# --- Shared fakes --------------------------------------------------------


class _FakeAssessmentRepository(AssessmentRepository):
    def __init__(self, assessments: dict[str, Assessment] | None = None) -> None:
        self._assessments = assessments or {}
        self.saved: list[Assessment] = []

    def get(self, assessment_id: AssessmentId) -> Assessment:
        a = self._assessments.get(str(assessment_id))
        if a is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return a

    def save(self, assessment: Assessment) -> None:
        self._assessments[str(assessment.id)] = assessment
        self.saved.append(assessment)

    def list(self, *, limit: int = 50, offset: int = 0) -> AssessmentPage:
        return AssessmentPage(items=tuple(list(self._assessments.values())[offset : offset + limit]))

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> list[Assessment]:
        return []

    def find_running(self) -> list[Assessment]:
        return [a for a in self._assessments.values() if a.status is AssessmentStatus.RUNNING]

    def find_running_ids(self) -> list[str]:
        return [str(a.id) for a in self._assessments.values() if a.status is AssessmentStatus.RUNNING]

    def force_fail_running(self, assessment_id: str, reason: str) -> bool:
        a = self._assessments.get(assessment_id)
        if a is None or a.status is not AssessmentStatus.RUNNING:
            return False
        a.fail(reason)
        return True

    def delete(self, assessment_id: AssessmentId) -> None:
        del self._assessments[str(assessment_id)]

    def search_findings(self, **kwargs: Any) -> tuple[list[Any], int]:
        return [], 0


class _RecordingJobRunner:
    """Runs submitted jobs inline, synchronously."""

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class _NullScanner:
    """ScannerPort fallback — never used when a profile_id + planner select
    a scanner_executor path, but SubmitAssessment requires a ScannerPort."""

    def scan(self, target: Any, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        return []

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {}


class _FakeDiscovery:
    """ScannerDiscoveryService double returning scripted statuses."""

    def __init__(self, statuses: dict[str, ScannerStatus]) -> None:
        self._statuses = statuses

    def get_all_statuses(self) -> list[ScannerStatus]:
        return list(self._statuses.values())


def _status(scanner_id: str, name: str, *, installed: bool, usable: bool) -> ScannerStatus:
    return ScannerStatus(
        scanner_id=scanner_id,
        name=name,
        installed=installed,
        executable_path=f"/usr/bin/{scanner_id}" if installed else None,
        version="1.0" if installed else None,
        usable=usable,
        availability_reason=None if usable else f"{name!r} is not installed",
    )


class _ScriptedScannerExecutor:
    """ScannerExecutor double that succeeds every scanner it's told to run,
    except any id listed in ``leave_pending`` — used to simulate the
    orchestrator silently dropping a selected scanner (invariant test)."""

    def __init__(self, leave_pending: frozenset[str] = frozenset()) -> None:
        self._leave_pending = leave_pending

    def execute_all(
        self,
        target: Any,
        *,
        configs: Any = None,
        scanner_ids: Sequence[str] | None = None,
        execution_engine: AssessmentExecutionEngine | None = None,
        tracking_id: str | None = None,
    ) -> tuple[Any, ...]:
        for sid in scanner_ids or ():
            if sid in self._leave_pending:
                continue
            if execution_engine is not None and tracking_id is not None:
                execution_engine.start_scanner(tracking_id, sid)
                execution_engine.complete_scanner(tracking_id, sid, findings_count=0)
        return ()


_TARGET_VALUE_BY_TYPE: dict[TargetType, str] = {
    TargetType.IP_ADDRESS: "10.0.0.5",
    TargetType.NETWORK: "10.0.0.0/24",
    TargetType.HOSTNAME: "example.com",
    TargetType.URL: "http://example.com",
}


def _authorized_assessment(*, profile_id: str, target_type: TargetType = TargetType.IP_ADDRESS) -> Assessment:
    a = Assessment(
        assessment_id=AssessmentId("asmt-phase2a-ref"),
        target=Target(_TARGET_VALUE_BY_TYPE[target_type], target_type),
        profile_id=profile_id,
    )
    a.authorize(Authorization("test-user", datetime.now(UTC), scope="test-scope"))
    return a


# --- 1. Reference case: Run #4 reproduction -------------------------------


# Phase 2A migration review (item 2): the previous version of this fixture
# used a FAKE registry that reported trivy/nuclei as compatible and
# "succeeding" against an ip_address target. Under the REAL registry, trivy
# only declares HOSTNAME support - it can never run against ip_address, so
# "3 of 9 succeed" was fabricated, not a real possible outcome. Rebuilt
# against the REAL registry (_real_registry(), defined below) with discovery
# statuses matching Phase 1's OWN actually-recorded environment exactly
# (docs/E2E-EVIDENCE.md): nmap installed and usable (it ran and found 9
# things); nuclei installed but NOT usable (no templates - Defect 5,
# "Missing Nuclei templates: nuclei -update-templates", the exact message
# reproduced here); nikto not installed (Defect 8, blocked by Windows
# Defender). Under the real registry, gobuster/ffuf/zap are all structurally
# incompatible with ip_address regardless of discovery status, so their
# entries below are illustrative only (compatibility is checked first and
# wins).
#
# Real outcome this produces: 1 of 6 succeeds (Nmap) - matching BOTH Phase
# 1's actual recorded Run #4 result (E2E-EVIDENCE.md: "Nmap... actually ran
# and completed with 9 real findings" while every other scanner was either
# stuck pending or correctly skipped, never succeeded) AND this phase's own
# live DVWA re-verification (docs/STATUS.md: "1 of 9 (Nmap)"). Phase 1's
# real full-assessment run scheduled 9 scanners; Phase 2B Decision 1/2
# removed semgrep, trivy, and amass from the profile (they cannot take any
# target type KingSec's current model expresses - see
# assessment_profiles.py), so this fixture now only needs discovery
# statuses for full-assessment's current 6 scanners.
_STATUSES = {
    "nmap": _status("nmap", "Nmap", installed=True, usable=True),
    "nuclei": _status("nuclei", "Nuclei", installed=True, usable=False),
    "gobuster": _status("gobuster", "Gobuster", installed=True, usable=True),
    "ffuf": _status("ffuf", "FFUF", installed=True, usable=True),
    "zap": _status("zap", "OWASP ZAP", installed=True, usable=True),
    "nikto": _status("nikto", "Nikto", installed=False, usable=False),
}


def _build_reference_case_submit_assessment(
    repo: _FakeAssessmentRepository, engine: AssessmentExecutionEngine, *, leave_pending: frozenset[str] = frozenset()
) -> SubmitAssessment:
    planner = ExecutionPlanner(discovery=_FakeDiscovery(_STATUSES), registry=_real_registry())
    return SubmitAssessment(
        assessments=repo,
        scanner=_NullScanner(),
        job_runner=_RecordingJobRunner(),
        execution_engine=engine,
        planner=planner,
        scanner_executor=_ScriptedScannerExecutor(leave_pending=leave_pending),
    )


class TestReferenceCaseRun4Reproduction:
    """Reproduces the exact Run #4 defect from Phase 1 E2E-EVIDENCE.md.

    Under pre-Phase-2A code this scenario produced
    ``AssessmentStatus.COMPLETED`` ("88.0/100 — Sound") with no coverage
    warning anywhere, despite only 1 of the 9 scheduled scanners
    (Nmap) ever actually running — 6 were silently stuck at "pending"
    and 2 (Nuclei, Nikto) were correctly skipped but undisclosed. This
    test would fail against that code (it asserts ``COMPLETED_WITH_GAPS``
    and a verdict naming every non-running scanner) and passes against
    the fixed code.

    Phase 2B Decision 1/2 note: ``full-assessment`` now schedules 6
    scanners, not the original 9 (semgrep, trivy, and amass were removed
    from the profile — see assessment_profiles.py). The fixture below
    still models Phase 1's real 9-scanner environment via ``_STATUSES``
    for historical accuracy, but the planner only ever consults the
    scanners actually listed in the profile, so the assertions here
    check 6 scheduled / 1 succeeded / 5 non-succeeded, matching
    ``full-assessment``'s current shape.
    """

    def test_status_is_completed_with_gaps_not_completed(self) -> None:
        assessment = _authorized_assessment(profile_id="full-assessment")
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})
        engine = AssessmentExecutionEngine()
        use_case = _build_reference_case_submit_assessment(repo, engine)

        use_case.execute(SubmitAssessmentRequest(assessment_id=str(assessment.id), is_admin=True))

        result = repo.saved[-1]
        assert result.status == AssessmentStatus.COMPLETED_WITH_GAPS
        assert len(result.scanner_summary) == 6

        succeeded = [s for s in result.scanner_summary if s.status.is_success]
        non_succeeded = failed_scanners_in(result.scanner_summary)
        assert len(succeeded) == 1
        assert len(non_succeeded) == 5
        assert {s.name for s in succeeded} == {"Nmap"}

    def test_report_verdict_names_every_non_running_scanner(self) -> None:
        assessment = _authorized_assessment(profile_id="full-assessment")
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})
        engine = AssessmentExecutionEngine()
        use_case = _build_reference_case_submit_assessment(repo, engine)

        use_case.execute(SubmitAssessmentRequest(assessment_id=str(assessment.id), is_admin=True))
        result = repo.saved[-1]

        report = Report.from_assessment(result, generated_at=datetime.now(UTC))
        assert report.assessment_status == AssessmentStatus.COMPLETED_WITH_GAPS
        # Zero actionable findings would otherwise render "no action
        # required" - incomplete coverage must force action_required=True
        # regardless (this is the exact Run #4 defect: a clean-looking
        # score hiding a scan that mostly didn't happen).
        assert report.verdict.action_required is True
        for name in ("Nuclei", "Gobuster", "FFUF", "OWASP ZAP", "Nikto"):
            assert name in report.verdict.headline, f"{name!r} missing from verdict headline"


# --- 2. Planner/orchestrator invariant ------------------------------------


class TestPlannerOrchestratorInvariant:
    def test_selected_scanner_left_non_terminal_fails_loudly(self) -> None:
        """If the executor is given a selected scanner and never brings it
        to a terminal state, the assessment must end up FAILED - not
        silently COMPLETED/COMPLETED_WITH_GAPS with that scanner frozen at
        PENDING forever (the exact structural shape of the Run #4 root
        cause, reintroduced at a different layer)."""
        assessment = _authorized_assessment(profile_id="full-assessment")
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})
        engine = AssessmentExecutionEngine()
        use_case = _build_reference_case_submit_assessment(repo, engine, leave_pending=frozenset({"nmap"}))

        use_case.execute(SubmitAssessmentRequest(assessment_id=str(assessment.id), is_admin=True))

        result = repo.saved[-1]
        assert result.status == AssessmentStatus.FAILED


def _permissive_statuses(scanner_ids: tuple[str, ...]) -> dict[str, ScannerStatus]:
    """Fake discovery: every scanner reports installed+usable. Deliberately
    fake — binary presence on the test machine is an environment concern
    unrelated to the structural property under test below. What must NOT
    be fake is target-type COMPATIBILITY, which is why this is paired with
    the real registry (_real_registry()), never a stub, in every test in
    this module from here down."""
    return {sid: _status(sid, sid.title(), installed=True, usable=True) for sid in scanner_ids}


def _real_registry() -> InMemoryPluginRegistry:
    """The REAL scanner plugin registry, wired exactly as
    composition.py's register_scanner() does (same function, default
    Settings()), so ``is_compatible()`` reflects each real plugin's own
    declared ``target_types`` — never a stub.

    Correction 2(d) review finding: this test file's matrix test
    previously used a permissive fake registry (`_PermissiveRegistry`,
    now removed) that reported every scanner compatible with every
    target type unconditionally. That could never have caught the real
    web-scan/nmap defect (nmap never declares URL support, but web-scan
    required it) — a test asserting an invariant against a fabricated
    registry proves less than it appears to. This is the real one.
    """
    container = Container()
    register_scanner(container, Settings())
    return container.resolve(ScannerPluginRegistry)  # type: ignore[return-value]


def _all_profile_target_type_pairs() -> list[tuple[str, TargetType]]:
    """Every (profile_id, target_type) combination the real planner supports -
    built from the planner's own profile registry, not hand-copied, so this
    list can never silently drift out of sync with assessment_profiles.py."""
    planner = ExecutionPlanner()
    pairs: list[tuple[str, TargetType]] = []
    for profile in planner.list_profiles():
        for tt in profile.supported_target_types:
            pairs.append((profile.id, tt))
    return pairs


class TestProfileRequiredScannersAreTargetTypeCompatible:
    """Phase 2B Task 1 review: the original spec here was wrong. "Compatible
    with at least one supported target type" lets a profile declare support
    for a target type under which its required scanner can NEVER run - the
    exact shape of the code-review/container-scan defect (semgrep/trivy
    declare HOSTNAME only, but both profiles also claim IP_ADDRESS support).
    A profile that "can proceed" for HOSTNAME but silently can never proceed
    for one of its OTHER declared types is exactly the web-scan/nmap defect
    class, just confined to a subset of the profile's targets instead of
    all of them.

    Strengthened: every required scanner must be compatible with EVERY
    target type the profile declares it supports - not merely one of them.

    Uses the REAL plugin registry's declared target_types (see
    _real_registry()), not a stub — a fake registry could never fail this
    test even with a genuinely broken profile.
    """

    def test_every_required_scanner_supports_every_declared_profile_target_type(self) -> None:
        registry = _real_registry()
        planner = ExecutionPlanner()
        violations = []
        for profile in planner.list_profiles():
            for scanner_id in profile.required_scanners:
                incompatible_types = [
                    tt
                    for tt in profile.supported_target_types
                    if not registry.is_compatible(ScannerId(scanner_id), tt)
                ]
                if incompatible_types:
                    violations.append(
                        f"profile {profile.id!r}: required scanner {scanner_id!r} is NOT compatible "
                        f"with {[t.value for t in incompatible_types]}, a target type this profile "
                        f"declares support for"
                    )
        assert not violations, "\n".join(violations)


class TestPlannerOrchestratorInvariantAcrossFullMatrix:
    """Correction 2(d): the executed set must equal the SELECTED set, across
    EVERY profile x every target_type that profile supports - not just one
    hand-picked combination. Built from ExecutionPlanner.list_profiles()
    itself (8 profiles x 1-3 supported target types each = 16 combinations
    at the time this was written), so a new profile is automatically
    covered without anyone remembering to extend this test.

    Uses the REAL plugin registry (_real_registry()) for compatibility, so
    a scanner incompatible with a given target type in THIS test is
    incompatible for the exact same reason it would be in production. The
    expected outcome for each combination is computed FROM that real
    compatibility data, not hardcoded to "everything succeeds": a required
    scanner that's really incompatible must produce a clean FAILED
    assessment (never a silent proceed), and an optional one must produce
    COMPLETED_WITH_GAPS naming the gap — never a blanket SUCCEEDED
    assumption that would hide exactly this class of defect.
    """

    @pytest.mark.parametrize("profile_id,target_type", _all_profile_target_type_pairs())
    def test_plan_and_execution_reach_the_honest_outcome_for_real_compatibility(
        self, profile_id: str, target_type: TargetType
    ) -> None:
        registry = _real_registry()
        planner_probe = ExecutionPlanner()
        profile = planner_probe.get_profile(profile_id)
        assert profile is not None
        planner = ExecutionPlanner(
            discovery=_FakeDiscovery(_permissive_statuses(profile.scanners)),
            registry=registry,
        )

        plan = planner.plan(profile_id, "target-value", target_type)

        # plan() always decides every scanner exactly once (Correction 2b) -
        # true regardless of real compatibility.
        decided_ids = (
            {e.scanner_id for e in plan.selected_scanners}
            | {e.scanner_id for e in plan.skipped_scanners}
            | {e.scanner_id for e in plan.unavailable_scanners}
        )
        assert decided_ids == set(profile.scanners)

        required_incompatible = [
            sid for sid in profile.required_scanners if not registry.is_compatible(ScannerId(sid), target_type)
        ]

        assessment = _authorized_assessment(profile_id=profile_id, target_type=target_type)
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})
        engine = AssessmentExecutionEngine()
        use_case = SubmitAssessment(
            assessments=repo,
            scanner=_NullScanner(),
            job_runner=_RecordingJobRunner(),
            execution_engine=engine,
            planner=planner,
            scanner_executor=_ScriptedScannerExecutor(),
        )
        use_case.execute(SubmitAssessmentRequest(assessment_id=str(assessment.id), is_admin=True))
        result = repo.saved[-1]

        if required_incompatible:
            # A required scanner that's really incompatible must fail the
            # plan cleanly, BEFORE any scanning starts - never silently
            # proceed with it dropped (the web-scan/nmap defect class).
            assert plan.can_proceed is False
            assert result.status == AssessmentStatus.FAILED
            assert result.failure_reason
            return

        assert plan.can_proceed is True
        compatible_ids = {sid for sid in profile.scanners if registry.is_compatible(ScannerId(sid), target_type)}
        incompatible_ids = set(profile.scanners) - compatible_ids
        assert {e.scanner_id for e in plan.selected_scanners} == compatible_ids

        assert {s.scanner_id for s in result.scanner_summary} == set(profile.scanners)
        if incompatible_ids:
            # Optional scanners really incompatible with this target type
            # must show as an honest, named gap - COMPLETED_WITH_GAPS, not
            # a blanket SUCCEEDED that erases the fact they never ran.
            assert result.status == AssessmentStatus.COMPLETED_WITH_GAPS
        else:
            assert result.status == AssessmentStatus.COMPLETED
        for s in result.scanner_summary:
            if s.scanner_id in compatible_ids:
                assert s.status.is_success
            else:
                assert s.status.is_skip


# --- 3. plan() always returns a full decision -----------------------------


class TestPlanCoversEveryScanner:
    def test_full_assessment_plan_decides_every_scanner_exactly_once(self) -> None:
        planner = ExecutionPlanner(discovery=_FakeDiscovery(_STATUSES), registry=_real_registry())
        plan = planner.plan("full-assessment", "10.0.0.5", TargetType.IP_ADDRESS)

        profile = planner.get_profile("full-assessment")
        assert profile is not None

        decided_ids = (
            {e.scanner_id for e in plan.selected_scanners}
            | {e.scanner_id for e in plan.skipped_scanners}
            | {e.scanner_id for e in plan.unavailable_scanners}
        )
        assert decided_ids == set(profile.scanners)
        # No scanner appears in more than one bucket.
        total_entries = len(plan.selected_scanners) + len(plan.skipped_scanners) + len(plan.unavailable_scanners)
        assert total_entries == len(profile.scanners)


class TestDoctorAgreesWithPlanner:
    """Task 3a's required test: kingsec doctor's per-scanner verdict must
    match the planner's real selection decision for that scanner, across
    EVERY profile - derived from the exact same ScannerDiscoveryService/
    ScannerPluginRegistry the planner itself uses (_doctor.py calls
    bootstrap.composition.build_execution_planner(), the identical
    construction _register_adapters() uses for the real, running app),
    never a second, independently-derived check that could silently
    disagree with it.

    Uses ``_STATUSES`` (mixed usable/not-usable, not the permissive
    fixture) so this actually exercises doctor's "NOT usable" branch, not
    only the trivial all-usable case.
    """

    @pytest.mark.parametrize("profile_id,target_type", _all_profile_target_type_pairs())
    def test_doctor_verdict_matches_plan_for_every_scanner(self, profile_id: str, target_type: TargetType) -> None:
        from kingsec._doctor import _target_types_served

        registry = _real_registry()
        planner = ExecutionPlanner(discovery=_FakeDiscovery(_STATUSES), registry=registry)
        profile = planner.get_profile(profile_id)
        assert profile is not None

        plan = planner.plan(profile_id, "target-value", target_type)
        plan_by_id = {
            e.scanner_id: e
            for e in (*plan.selected_scanners, *plan.skipped_scanners, *plan.unavailable_scanners)
        }
        statuses = {s.scanner_id: s for s in planner.discovery.get_all_statuses()}

        for scanner_id in profile.scanners:
            entry = plan_by_id[scanner_id]
            status = statuses[scanner_id]

            doctor_target_types = _target_types_served(planner, scanner_id)
            doctor_serves_this_type = target_type in doctor_target_types
            # doctor's "which target types it can serve" must match
            # is_compatible() exactly - the same primitive plan() itself
            # calls (assessment_profiles.py's plan(), the registry.is_compatible
            # check).
            assert doctor_serves_this_type == registry.is_compatible(ScannerId(scanner_id), target_type)

            if not doctor_serves_this_type:
                assert entry.selected is False
                assert entry.skip_state == ScannerRunState.SKIPPED_INCOMPATIBLE
            elif status.usable:
                assert entry.selected is True, (
                    f"{scanner_id!r}: doctor says usable and compatible with {target_type.value!r}, "
                    f"but the planner did not select it for profile {profile_id!r}"
                )
            else:
                assert entry.selected is False, (
                    f"{scanner_id!r}: doctor says NOT usable, but the planner selected it anyway "
                    f"for profile {profile_id!r} - doctor and the planner disagree"
                )
                assert entry.skip_state in (
                    ScannerRunState.SKIPPED_ASSET_MISSING,
                    ScannerRunState.SKIPPED_BINARY_MISSING,
                )


# --- 4. Wordlist detection on a real Windows-style path -------------------


class TestWordlistDetectionOnWindowsPath:
    def test_check_asset_resolves_a_real_windows_style_wordlist_path(self, tmp_path: Any) -> None:
        wordlist = tmp_path / "common.txt"
        wordlist.write_text("admin\nroot\n")
        # tmp_path is a native path on this platform; on Windows this is a
        # real backslash-separated path (Correction 4's exact regression
        # target - the old hardcoded '/usr/share/wordlists' check always
        # reported "missing" on a path shaped like this).
        asset = AssetRequirement(name="Wordlist file", kind="file", path=str(wordlist))
        assert _check_asset(asset) is True

    def test_check_asset_reports_missing_for_a_nonexistent_path(self, tmp_path: Any) -> None:
        asset = AssetRequirement(name="Wordlist file", kind="file", path=str(tmp_path / "does-not-exist.txt"))
        assert _check_asset(asset) is False

    def test_ffuf_manifest_wordlist_asset_is_required_not_optional(self) -> None:
        """Correction 4's other half: wordlist must be a REQUIRED asset,
        not silently optional (the old flag that masked this exact class
        of defect for ffuf/gobuster while nuclei's templates were
        required)."""
        from kingsec.application.scanner_discovery import _SCANNER_MANIFEST

        wordlist_asset = next(a for a in _SCANNER_MANIFEST["ffuf"]["assets"] if a.name == "Wordlist file")
        assert wordlist_asset.optional is False


# --- 5. FIX 9: orphaned RUNNING assessment resolves at startup ------------


class TestResolveOrphanedAssessments:
    def test_running_assessment_resolves_to_failed(self) -> None:
        assessment = _authorized_assessment(profile_id="quick-scan")
        assessment.start()  # AUTHORIZED -> RUNNING, simulating a crash mid-execution
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})
        assert len(repo.find_running()) == 1

        resolved_count = ResolveOrphanedAssessments(repo).execute()

        assert resolved_count == 1
        resolved = repo.get(assessment.id)
        assert resolved.status == AssessmentStatus.FAILED
        assert resolved.failure_reason
        assert repo.find_running() == []

    def test_no_running_assessments_is_a_no_op(self) -> None:
        assessment = _authorized_assessment(profile_id="quick-scan")  # AUTHORIZED, not RUNNING
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})

        resolved_count = ResolveOrphanedAssessments(repo).execute()

        assert resolved_count == 0
        assert repo.get(assessment.id).status == AssessmentStatus.AUTHORIZED


# --- 6. Phase 2A-b: coverage-aware verdict, score, and rendered report ----


class TestCoverageAwareVerdictAndScore:
    """Phase 2A-b: the Run #4 defect reproduced itself on the report's own
    score/gauge page - a reassuring "SOUND" band and score narrative sat
    right next to a cover-page coverage warning nobody reading page 2
    would ever see. A COMPLETED_WITH_GAPS report must never render a
    reassuring band label or a reassuring verdict headline, and the score
    must always carry its real scanner denominator.
    """

    def _completed_with_gaps_report(self) -> Report:
        assessment = _authorized_assessment(profile_id="full-assessment")
        repo = _FakeAssessmentRepository({str(assessment.id): assessment})
        engine = AssessmentExecutionEngine()
        use_case = _build_reference_case_submit_assessment(repo, engine)
        use_case.execute(SubmitAssessmentRequest(assessment_id=str(assessment.id), is_admin=True))
        result = repo.saved[-1]
        assert result.status == AssessmentStatus.COMPLETED_WITH_GAPS
        return Report.from_assessment(result, generated_at=datetime.now(UTC))

    def test_verdict_headline_leads_with_coverage_not_findings(self) -> None:
        report = self._completed_with_gaps_report()
        headline = report.verdict.headline
        assert headline.startswith("Incomplete assessment"), (
            f"headline must lead with coverage, not findings: {headline!r}"
        )
        # The old ordering put the reassuring findings clause first; make
        # sure it is not merely reworded but genuinely demoted to second.
        assert "scanners ran" in headline.split(".")[0]

    def test_rendered_report_never_shows_a_reassuring_band_or_headline(self) -> None:
        report = self._completed_with_gaps_report()
        html = render_report_html(report)
        for reassuring in ("SOUND", "Sound", "generally sound standing", "Strong"):
            assert reassuring not in html, f"reassuring text {reassuring!r} must never appear"
        assert "Partial Coverage" in html
        exec_section = html.split('<section id="executive-summary">')[1].split("</section>")[0]
        assert "Minor issues found" not in exec_section.split(".")[0], (
            "the findings clause must not be the first sentence"
        )

    def test_score_string_includes_scanner_denominator(self) -> None:
        report = self._completed_with_gaps_report()
        html = render_report_html(report)
        succeeded = sum(1 for s in report.scanner_summary if s.status.is_success)
        total = len(report.scanner_summary)
        assert f"based on {succeeded} of {total} scanners" in html
        assert "Not a posture score" in html

    def test_findings_table_recommendation_count_matches_remediation_section(self) -> None:
        report = self._completed_with_gaps_report()
        html = render_report_html(report)
        # Every entry here (Nmap "Open port N/tcp" findings) has a generic
        # fallback recommendation - the table's count column must reflect
        # that, not the raw (often-empty) AI/analyst recommendations list.
        for entry in report.entries:
            assert len(entry.effective_recommendations) > 0
        assert "<td>0</td>" not in html.split('<section id="findings">')[1].split("</section>")[0]

    def test_ai_unavailable_callout_has_no_operator_setup_instructions(self) -> None:
        report = self._completed_with_gaps_report()
        html = render_report_html(report)
        assert "Configure a provider in Settings" not in html
        assert "not available for this report" in html
