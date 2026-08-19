"""Phase 03 reproduction + regression: failure_reason must not leak internals.

Step 4 of the Phase 03 prompt requires verifying whether failure_reason risks
exposing stack traces, absolute paths, internal hostnames, subprocess command
lines, or credentials. Inspection of every Assessment.fail() call site
(start_assessment.py, submit_assessment.py) found both pass raw str(exc) from
a broad `except Exception` - which, for an unvetted/unexpected exception, can
carry exactly that kind of detail. KingSec already has a safe/unsafe message
split for exactly this situation (kingsec.shared.errors.KingSecError.message
vs .user_message, and the same "safe by construction" property already holds
for kingsec.application.errors.ApplicationError, whose subclasses are all
deliberately-authored business-rule messages, not wrapped raw exceptions -
see ExecutionPlanUnsatisfiedError, already asserted verbatim into
failure_reason by two existing, unmodified tests in test_start_assessment.py
and test_submit_assessment.py). This file proves the two call sites use that
existing distinction correctly:

    KingSecError            -> exc.user_message   (already the safe one)
    ApplicationError        -> str(exc)            (already safe: developer-authored)
    anything else           -> KingSecError.default_user_message (unvetted; assume unsafe)

Written FIRST, before any fix. safe_failure_message does not exist yet, so
these fail at collection (ImportError) until _support.py adds it, and the
use-case-level tests fail because the call sites still pass raw str(exc).
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.unit.application.conftest import InMemoryAssessmentRepository

from kingsec.application._support import safe_failure_message
from kingsec.application.dto import StartAssessmentRequest
from kingsec.application.errors import ApplicationError, ExecutionPlanUnsatisfiedError
from kingsec.application.use_cases.start_assessment import StartAssessment
from kingsec.domain import Assessment, Authorization, Target, TargetType
from kingsec.domain.enums import AssessmentStatus
from kingsec.shared.errors import KingSecError, ScannerError


def _authorized(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessments.save(assessment)
    return assessment


class TestSafeFailureMessage:
    """Direct unit coverage of the three branches."""

    def test_kingsec_error_uses_default_user_message_not_internal_message(self) -> None:
        exc = ScannerError("subprocess /opt/scanners/nmap failed: Permission denied: /etc/nmap/nmap-services")
        assert safe_failure_message(exc) == "The security scan could not be completed."

    def test_kingsec_error_uses_explicit_user_message_when_set(self) -> None:
        exc = KingSecError("internal: pool exhausted at db-primary.internal:5432", user_message="Scan could not start.")
        assert safe_failure_message(exc) == "Scan could not start."

    def test_application_error_is_preserved_verbatim(self) -> None:
        # ApplicationError subclasses are deliberately-authored, developer-
        # controlled business-rule messages (not wrapped raw exceptions) -
        # safe by construction, same spirit as KingSecError.user_message.
        exc = ExecutionPlanUnsatisfiedError("Required scanner 'Nmap' is not installed.")
        assert safe_failure_message(exc) == "Required scanner 'Nmap' is not installed."

    def test_unvetted_exception_collapses_to_generic_safe_message(self) -> None:
        exc = FileNotFoundError("[Errno 2] No such file or directory: '/opt/scanners/nmap/nmap.xml'")
        assert safe_failure_message(exc) == KingSecError.default_user_message
        assert "/opt/scanners" not in safe_failure_message(exc)

    def test_connection_error_collapses_to_generic_safe_message(self) -> None:
        exc = ConnectionError("Connection refused: internal-scanner-host.corp.local:9200")
        assert safe_failure_message(exc) == KingSecError.default_user_message
        assert "internal-scanner-host" not in safe_failure_message(exc)


class _RaisingScanner:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def scan(self, target: Any, scanner_ids: Any = None) -> Any:
        raise self._exc

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"nmap": "Nmap"}


class TestStartAssessmentFailureReasonSanitization:
    def test_unvetted_scanner_exception_does_not_leak_into_failure_reason(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _authorized(assessments)
        raw = FileNotFoundError("[Errno 2] No such file or directory: '/opt/scanners/nmap/nmap.xml'")
        use_case = StartAssessment(assessments, _RaisingScanner(raw))

        with pytest.raises(FileNotFoundError):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.FAILED
        assert stored.failure_reason == KingSecError.default_user_message
        assert "/opt/scanners" not in (stored.failure_reason or "")

    def test_kingsec_scanner_error_exposes_only_its_user_message(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _authorized(assessments)
        exc = ScannerError("nmap exited 1: command was /opt/scanners/nmap -sV --script vuln 10.0.0.5")
        use_case = StartAssessment(assessments, _RaisingScanner(exc))

        with pytest.raises(ScannerError):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        stored = assessments.get(assessment.id)
        assert stored.failure_reason == "The security scan could not be completed."
        assert "/opt/scanners" not in (stored.failure_reason or "")

    def test_application_error_reason_still_reaches_failure_reason_verbatim(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        # Same intentional-message class as ExecutionPlanUnsatisfiedError,
        # which two EXISTING tests already rely on seeing verbatim in
        # failure_reason - this proves the sanitization fix keeps that
        # legitimate case intact, not just the new unsafe-message case.
        assessment = _authorized(assessments)

        class _NamedApplicationError(ApplicationError):
            pass

        exc = _NamedApplicationError("Target is out of the authorized scope.")
        use_case = StartAssessment(assessments, _RaisingScanner(exc))

        with pytest.raises(ApplicationError):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        stored = assessments.get(assessment.id)
        assert stored.failure_reason == "Target is out of the authorized scope."


class _InlineJobRunner:
    """Runs the submitted job synchronously, in-thread - deterministic for tests."""

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class TestSubmitAssessmentFailureReasonSanitization:
    """submit_assessment.py has its OWN `except Exception as exc: assessment.fail(...)`
    call site, separate from start_assessment.py's - both needed the fix."""

    def test_unvetted_scanner_exception_does_not_leak_into_failure_reason(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        from kingsec.application.dto import SubmitAssessmentRequest
        from kingsec.application.submit_assessment import SubmitAssessment

        assessment = _authorized(assessments)
        raw = ConnectionError("Connection refused: internal-scanner-host.corp.local:9200")
        use_case = SubmitAssessment(assessments, _RaisingScanner(raw), _InlineJobRunner())

        use_case.execute(SubmitAssessmentRequest(str(assessment.id), is_admin=True))

        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.FAILED
        assert stored.failure_reason == KingSecError.default_user_message
        assert "internal-scanner-host" not in (stored.failure_reason or "")

    def test_application_error_reason_still_reaches_failure_reason_verbatim(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        from kingsec.application.dto import SubmitAssessmentRequest
        from kingsec.application.submit_assessment import SubmitAssessment

        assessment = _authorized(assessments)
        exc = ExecutionPlanUnsatisfiedError("Required scanner 'Nmap' is not installed.")
        use_case = SubmitAssessment(assessments, _RaisingScanner(exc), _InlineJobRunner())

        use_case.execute(SubmitAssessmentRequest(str(assessment.id), is_admin=True))

        stored = assessments.get(assessment.id)
        assert stored.failure_reason == "Required scanner 'Nmap' is not installed."
