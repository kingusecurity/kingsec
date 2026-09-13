"""Service ports — abstract contracts for external capabilities.

Each of these will be implemented by an infrastructure adapter later:
    ScannerPort         -> a scanner engine (e.g. Nuclei) that discovers findings
    AIPort              -> a bring-your-own-key AI client that enriches findings
    ReportGeneratorPort -> a renderer (e.g. WeasyPrint) that produces a document

The application depends on these abstractions, never on the concrete engines, so
the scanning/AI/reporting technology can change without touching use-case logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from kingsec.application.dto import RenderedReport
from kingsec.domain import Finding, Recommendation, Report, Target


class ScannerPort(ABC):
    """Runs a security scan against a target and returns domain findings."""

    @abstractmethod
    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` and return the findings discovered (possibly empty).

        ``scanner_ids``, when given, narrows execution to that subset of
        otherwise-compatible scanners (e.g. an assessment profile's
        selection) instead of every compatible one. ``None`` (the
        default) means "no narrowing" — every caller written before this
        parameter existed keeps its exact prior behavior unchanged.
        """

    @abstractmethod
    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """Return the scanners that would actually run for ``target``.

        Maps scanner_id -> human-readable display name. Callers use this to
        report *what is about to run* before calling ``scan()`` — ``scan()``
        itself is an opaque call that returns only findings, with no way to
        report back which individual scanners it attempted.
        """


class AIPort(ABC):
    """Uses an AI provider to enrich a finding with remediation guidance."""

    @abstractmethod
    def recommend(self, finding: Finding) -> Recommendation:
        """Return an AI-generated remediation recommendation for ``finding``."""

    @abstractmethod
    def explain_business_risk(self, finding: Finding) -> str:
        """Return a plain-language, business-risk explanation of ``finding``.

        Distinct from ``recommend()``: this is prose for a non-technical
        reader (what the finding means for the business), not remediation
        guidance.
        """


class ReportGeneratorPort(ABC):
    """Renders a domain report into a deliverable artifact (PDF/HTML/etc.)."""

    @abstractmethod
    def render(self, report: Report, *, format: str | None = None) -> RenderedReport:
        """Render ``report`` and return the artifact bytes + metadata.

        Phase 2A FIX 7: ``format`` is an optional per-call override
        (``"pdf"`` or ``"html"``); ``None`` (the default, used by every
        pre-existing caller) renders in whichever format the adapter was
        configured with at startup, preserving prior behavior exactly.
        """
