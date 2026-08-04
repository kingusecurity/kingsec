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
    def scan(self, target: Target) -> Sequence[Finding]:
        """Scan ``target`` and return the findings discovered (possibly empty)."""


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
    def render(self, report: Report) -> RenderedReport:
        """Render ``report`` and return the artifact bytes + metadata."""
