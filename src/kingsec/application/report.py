"""Report Domain Model.

Aggregation of all pipeline outputs — normalization, correlation,
enrichment, risk scoring, and attack path analysis — into a single
report structure. Pure application-layer value objects only.

Design principles:
    * Immutable value objects (frozen dataclasses).
    * No rendering, serialization, or infrastructure import.
    * Each model captures one distinct section of the final report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.attack_path import AttackGraph
    from kingsec.application.correlation import CorrelatedFinding
    from kingsec.application.enrichment import EnrichedFinding
    from kingsec.application.normalization import NormalizedFinding
    from kingsec.application.risk import RiskAssessment


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutiveSummary:
    """High-level summary for management stakeholders.

    Contains aggregate counts and severity distribution across the
    entire pipeline.
    """

    total_findings: int
    total_correlated: int
    total_enriched: int
    total_risk_assessments: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    top_risk_score: int
    average_risk_score: float
    total_assets: int
    summary_text: str

    def __post_init__(self) -> None:
        if self.total_findings < 0:
            raise ValueError("total_findings must not be negative")
        if self.total_correlated < 0:
            raise ValueError("total_correlated must not be negative")
        if self.total_enriched < 0:
            raise ValueError("total_enriched must not be negative")
        if self.total_risk_assessments < 0:
            raise ValueError("total_risk_assessments must not be negative")
        if not 0 <= self.top_risk_score <= 100:
            raise ValueError("top_risk_score must be between 0 and 100")
        if not 0.0 <= self.average_risk_score <= 100.0:
            raise ValueError("average_risk_score must be between 0 and 100")
        if not self.summary_text:
            raise ValueError("summary_text must not be empty")

    @property
    def total_severe(self) -> int:
        """Total findings with severity Critical or High."""
        return self.critical_count + self.high_count


@dataclass(frozen=True)
class TechnicalSummary:
    """Technical breakdown for engineering and security teams.

    Severity distribution, category breakdown, and scanner coverage
    details.
    """

    total_findings: int
    total_correlations: int
    total_enriched: int
    total_risk_assessments: int
    severity_breakdown: dict[str, int] = field(hash=False)
    category_breakdown: dict[str, int] = field(hash=False)
    scanner_coverage: dict[str, int] = field(hash=False)

    def __post_init__(self) -> None:
        if self.total_findings < 0:
            raise ValueError("total_findings must not be negative")
        if self.total_correlations < 0:
            raise ValueError("total_correlations must not be negative")
        if self.total_enriched < 0:
            raise ValueError("total_enriched must not be negative")
        if self.total_risk_assessments < 0:
            raise ValueError("total_risk_assessments must not be negative")


@dataclass(frozen=True)
class RiskSummary:
    """Risk score distribution and overall statistics."""

    score_distribution: dict[str, int] = field(hash=False)
    average_score: float
    highest_score: int
    lowest_score: int
    top_risk_factors: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.score_distribution:
            raise ValueError("score_distribution must not be empty")
        if not 0.0 <= self.average_score <= 100.0:
            raise ValueError("average_score must be between 0 and 100")
        if not 0 <= self.highest_score <= 100:
            raise ValueError("highest_score must be between 0 and 100")
        if not 0 <= self.lowest_score <= 100:
            raise ValueError("lowest_score must be between 0 and 100")
        if self.lowest_score > self.highest_score:
            raise ValueError("lowest_score must not exceed highest_score")


@dataclass(frozen=True)
class AssetEntry:
    """A single asset entry in the asset breakdown."""

    asset: str
    finding_count: int
    highest_risk_score: int
    average_risk_score: float

    def __post_init__(self) -> None:
        if not self.asset:
            raise ValueError("asset must not be empty")
        if self.finding_count < 0:
            raise ValueError("finding_count must not be negative")
        if not 0 <= self.highest_risk_score <= 100:
            raise ValueError("highest_risk_score must be between 0 and 100")
        if not 0.0 <= self.average_risk_score <= 100.0:
            raise ValueError("average_risk_score must be between 0 and 100")


@dataclass(frozen=True)
class AssetSummary:
    """Breakdown of all findings grouped by affected asset."""

    entries: tuple[AssetEntry, ...]
    total_assets: int

    def __post_init__(self) -> None:
        if not self.entries:
            raise ValueError("entries must not be empty")
        if self.total_assets < 0:
            raise ValueError("total_assets must not be negative")

    @property
    def total_findings(self) -> int:
        return sum(e.finding_count for e in self.entries)


@dataclass(frozen=True)
class FindingEntry:
    """A single finding entry shown in the findings section."""

    correlation_id: str
    title: str
    severity: str
    category: str
    confidence: float
    scanner_sources: tuple[str, ...]
    affected_assets: tuple[str, ...]
    service: str | None
    port: int | None
    protocol: str | None
    attack_surface: str | None
    risk_score: int
    risk_level: str
    priority: str

    def __post_init__(self) -> None:
        if not self.correlation_id:
            raise ValueError("correlation_id must not be empty")
        if not self.title:
            raise ValueError("title must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")


@dataclass(frozen=True)
class FindingSection:
    """All enriched and risk-assessed findings in the report."""

    entries: tuple[FindingEntry, ...]
    total_count: int
    severity_breakdown: dict[str, int] = field(hash=False)

    def __post_init__(self) -> None:
        if not self.entries:
            raise ValueError("entries must not be empty")
        if self.total_count < 0:
            raise ValueError("total_count must not be negative")
        if not self.severity_breakdown:
            raise ValueError("severity_breakdown must not be empty")


@dataclass(frozen=True)
class AttackPathSection:
    """All discovered attack paths in the report."""

    total_paths: int
    highest_score: int
    average_score: float
    graph: "AttackGraph" = field(hash=False)

    def __post_init__(self) -> None:
        if self.total_paths < 0:
            raise ValueError("total_paths must not be negative")
        if not 0 <= self.highest_score <= 100:
            raise ValueError("highest_score must be between 0 and 100")
        if not 0.0 <= self.average_score <= 100.0:
            raise ValueError("average_score must be between 0 and 100")


@dataclass(frozen=True)
class RecommendationEntry:
    """A single remediation recommendation for a finding."""

    finding_title: str
    severity: str
    risk_score: int
    correlation_id: str
    recommendations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.finding_title:
            raise ValueError("finding_title must not be empty")
        if not self.correlation_id:
            raise ValueError("correlation_id must not be empty")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if not self.recommendations:
            raise ValueError("recommendations must not be empty")


@dataclass(frozen=True)
class RecommendationSection:
    """All remediation recommendations, sorted by priority."""

    entries: tuple[RecommendationEntry, ...]
    total_recommendations: int

    def __post_init__(self) -> None:
        if not self.entries:
            raise ValueError("entries must not be empty")
        if self.total_recommendations < 0:
            raise ValueError("total_recommendations must not be negative")


@dataclass(frozen=True)
class Appendix:
    """Supplementary metadata about the report generation."""

    scanner_versions: dict[str, str | None] = field(hash=False)
    total_plugins: int
    generated_at: datetime
    generated_by: str

    def __post_init__(self) -> None:
        if not self.scanner_versions:
            raise ValueError("scanner_versions must not be empty")
        if self.total_plugins < 0:
            raise ValueError("total_plugins must not be negative")
        if not self.generated_by:
            raise ValueError("generated_by must not be empty")


# ---------------------------------------------------------------------------
# Report aggregate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Report:
    """Complete aggregated security report.

    Aggregates the outputs of the full pipeline:
        * FindingNormalizer     → NormalizedFinding list
        * CorrelationEngine     → CorrelatedFinding list
        * FindingEnricher       → EnrichedFinding list
        * RiskScorer            → RiskAssessment list
        * AttackPathAnalyzer    → AttackGraph

    All sections are pre-computed and stored as frozen value objects.
    """

    report_id: str
    title: str
    created_at: datetime
    executive_summary: ExecutiveSummary
    technical_summary: TechnicalSummary
    risk_summary: RiskSummary
    asset_summary: AssetSummary
    finding_section: FindingSection
    attack_path_section: AttackPathSection
    recommendation_section: RecommendationSection
    appendix: Appendix

    def __post_init__(self) -> None:
        if not self.report_id:
            raise ValueError("report_id must not be empty")
        if not self.title:
            raise ValueError("title must not be empty")

    @property
    def total_sections(self) -> int:
        """Number of sections in the report (excluding appendix)."""
        return 7
