"""Scanner integration tests: real subprocess + full persisted slice."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from kingsec.application import (
    CreateAssessment,
    CreateAssessmentRequest,
    GetAssessment,
    GetAssessmentRequest,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.domain import Severity, Target, TargetType
from kingsec.infrastructure.config.models import ScannerSettings
from kingsec.infrastructure.persistence import (
    LegacyAssessmentRepository,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from kingsec.infrastructure.scanner import NucleiScannerAdapter
from kingsec.infrastructure.scanner.errors import ScannerExecutionError

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)


def _adapter(binary: Path, **overrides) -> NucleiScannerAdapter:
    # Uses the REAL SubprocessCommandRunner (no runner override).
    return NucleiScannerAdapter(ScannerSettings(binary_path=str(binary), **overrides))


class TestRealSubprocess:
    def test_findings_are_parsed_from_real_process(self, make_fake_nuclei: Callable[[str], Path]) -> None:
        findings = _adapter(make_fake_nuclei("findings")).scan(_TARGET)
        assert len(findings) == 2
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].recommendations  # remediation mapped through

    def test_empty_output_is_no_findings(self, make_fake_nuclei: Callable[[str], Path]) -> None:
        assert _adapter(make_fake_nuclei("empty")).scan(_TARGET) == []

    def test_nonzero_exit_raises_scanner_error(self, make_fake_nuclei: Callable[[str], Path]) -> None:
        with pytest.raises(ScannerExecutionError) as excinfo:
            _adapter(make_fake_nuclei("error")).scan(_TARGET)
        assert excinfo.value.code == "KS-SCAN-001"

    def test_timeout_raises_scanner_error(self, make_fake_nuclei: Callable[[str], Path]) -> None:
        with pytest.raises(ScannerExecutionError, match="timed out"):
            _adapter(make_fake_nuclei("slow"), timeout_seconds=0.5).scan(_TARGET)

    def test_missing_binary_raises_scanner_error(self, tmp_path: Path) -> None:
        with pytest.raises(ScannerExecutionError, match="binary not found"):
            _adapter(tmp_path / "does-not-exist").scan(_TARGET)


class TestEndToEndSlice:
    """Scanner -> StartAssessment -> real SQLite persistence (Modules 4.1/4.2)."""

    def test_full_scan_and_persist(self, tmp_path: Path, make_fake_nuclei: Callable[[str], Path]) -> None:
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")
        create_schema(engine)
        assessments = LegacyAssessmentRepository(create_session_factory(engine))
        scanner = _adapter(make_fake_nuclei("findings"))

        try:
            created = CreateAssessment(assessments).execute(
                CreateAssessmentRequest("10.0.0.5", "ip_address", "tester", "10.0.0.5")
            )
            started = StartAssessment(assessments, scanner).execute(StartAssessmentRequest(created.assessment_id))

            assert started.status == "completed"
            assert started.findings_count == 2
            assert started.highest_severity == Severity.CRITICAL.label

            # Findings from the real scanner process are durably persisted.
            view = GetAssessment(assessments).execute(GetAssessmentRequest(created.assessment_id, is_admin=True))
            titles = {f.title for f in view.findings}
            assert "Critical RCE" in titles
        finally:
            engine.dispose()
