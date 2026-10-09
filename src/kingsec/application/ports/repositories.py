from __future__ import annotations

import builtins
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from kingsec.domain import Assessment, AssessmentId, Report, ScannerResult, Target

if TYPE_CHECKING:
    from kingsec.application.jobs import ScanJob


# ---------------------------------------------------------------------------
# Define Asset at the port boundary — it is a value object the persistence
# layer knows about but the domain does not currently model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    """A discovered network asset.

    Immutable once recorded.  The asset identifier is opaque to the domain
    — it is assigned by the persistence layer at creation time.
    """

    id: str
    target: Target
    discovered_at: datetime
    tags: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# AssessmentRepository  (exists — kept for completeness)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingProjection:
    """A read-only projection of a finding with its assessment context."""

    finding_id: str
    assessment_id: str
    target: str
    title: str
    description: str
    severity: str
    status: str
    discovered_at: str
    evidence_count: int
    recommendation_count: int


@dataclass(frozen=True, slots=True)
class AssessmentPage:
    """One page of assessments, honest about what couldn't be loaded.

    Phase 2B Task 2 Condition 1: a row that exists but cannot be
    reconstructed into a domain Assessment (a corrupted target_value, once
    Decision 3's validation tightening lands) must not silently vanish
    from a list, and must not fail the whole list either - both are the
    same "nothing found vs nothing looked" defect class logged in
    docs/STATUS.md. ``unreadable_ids`` carries the ids specifically (not
    only a count): the id column reads fine even when target_value does
    not, so it costs nothing to expose, and "row asmt-abc123 is
    unreadable" is actionable in a way "1 row unreadable" is not.
    """

    items: tuple[Assessment, ...]
    total: int
    unreadable_ids: tuple[str, ...] = ()


class AssessmentRepository(ABC):
    """Persists and retrieves :class:`Assessment` aggregates."""

    @abstractmethod
    def save(self, assessment: Assessment) -> None:
        """Insert or update the given assessment (upsert semantics)."""

    @abstractmethod
    def get(self, assessment_id: AssessmentId) -> Assessment:
        """Return the assessment for the id.

        Raises:
            AssessmentNotFoundError: If no row exists for this id.
            AssessmentDataCorruptedError: If the row exists but cannot be
                reconstructed (Phase 2B Task 2 Condition 1) - the caller
                asked for this specific row, so a silent skip or a
                misleading "not found" would both be dishonest.
        """

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        status: str | None = None,
        order_by: str = "created_at",
        order_dir: str = "desc",
        requesting_user: str = "",
        is_admin: bool = True,
    ) -> AssessmentPage:
        """Return one filtered, ordered page of assessments.

        Ownership and all filters are applied before pagination. ``total`` is
        the number of matching persisted rows before the page limit/offset.
        Implementations must allowlist ``order_by`` rather than interpolating
        caller-provided column names.

        Direct repository callers retain the historical unscoped listing by
        default. User-facing callers must always pass ``requesting_user`` and
        ``is_admin`` explicitly; ``ListAssessments`` does so before this
        boundary is reached.

        A row that cannot be reconstructed is excluded from ``items`` and
        its id is reported in ``unreadable_ids`` instead of failing the
        entire call (Phase 2B Task 2 Condition 1).
        """

    @abstractmethod
    def find_running(self) -> builtins.list[Assessment]:
        """Return every assessment currently in RUNNING status.

        Phase 2A FIX 9: the startup orphan-recovery pass uses this to find
        assessments a prior process crash left stuck mid-execution - a
        fresh process start means nothing returned here can legitimately
        still be executing.

        Phase 2B Task 2 Condition 2: ResolveOrphanedAssessments no longer
        calls this - see find_running_ids()/force_fail_running() below,
        which never construct a domain Assessment (and so can never fail
        on a corrupted target_value) since resolving an orphan never
        legitimately needed one. Kept here as a general capability for any
        other caller that genuinely needs the full aggregate.
        """

    @abstractmethod
    def find_running_ids(self) -> builtins.list[str]:
        """Return the ids of every assessment currently in RUNNING status.

        Phase 2B Task 2 Condition 2: reads ONLY the id and status columns -
        never target_value/target_type, so it can never fail on a
        corrupted row the way find_running() (which must fully
        reconstruct each Assessment, Target included) can. Paired with
        force_fail_running() so orphan recovery never needs a domain
        Assessment at all.
        """

    @abstractmethod
    def force_fail_running(self, assessment_id: str, reason: str) -> bool:
        """Force one assessment from RUNNING to FAILED without loading it.

        Phase 2B Task 2 Condition 2 - THE SINGLE SANCTIONED DOMAIN-BYPASS
        WRITE PATH, scoped to startup orphan recovery only. Must NOT become
        a general-purpose update method. A direct column write (status,
        failure_reason, and any other field Assessment.fail() mutates or
        that participates in optimistic concurrency - see the concrete
        implementation for the exact, enumerated field list) scoped to
        ``WHERE id = ? AND status = 'RUNNING'``, so it is a safe no-op if
        the row already moved on for any reason between find_running_ids()
        and this call. Returns whether a row was actually updated.

        This exists ONLY because orphan recovery's own logic
        (Assessment.fail() + save()) never actually needed a full domain
        Assessment - it needs "this id, currently RUNNING, becomes FAILED
        with this reason," nothing else. A corrupted target_value must not
        be able to leave an orphaned job stuck RUNNING forever - the exact
        "nothing found vs nothing looked" defect class logged in
        docs/STATUS.md, reintroduced through a path the Phase 2A invariant
        tests cannot see because they never construct a corrupted row.
        """

    @abstractmethod
    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> builtins.list[Assessment]:
        """Return every assessment linked to the given schedule occurrence.

        KSEC-100-01: the durable relationship
        (``Assessment.schedule_occurrence_id``) that lets a scheduled-
        assessment recovery mechanism distinguish "CreateAssessment already
        committed for this occurrence" from "it never happened" - without
        this, a crashed CREATING occurrence cannot be safely resumed
        without risking a duplicate real assessment. Normally returns 0 or
        1 rows; more than 1 indicates a corrupted/ambiguous state a caller
        must not silently resolve by picking one.
        """

    @abstractmethod
    def delete(self, assessment_id: AssessmentId) -> None:
        """Delete an assessment and all its children.

        Raises:
            AssessmentNotFoundError: If no assessment has that id.
        """

    @abstractmethod
    def search_findings(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        order_by: str = "discovered_at",
        order_dir: str = "desc",
        limit: int = 50,
        offset: int = 0,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[builtins.list[FindingProjection], int]:
        """Search findings across assessments with filters and pagination.

        Unless ``is_admin`` is True, results are restricted to findings
        whose assessment is owned by ``requesting_user``.

        Returns a tuple of (projections, total_count).
        """


# ---------------------------------------------------------------------------
# ReportRepository  (exists — kept for completeness)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportProjection:
    """A read-only projection of a report for list views."""

    assessment_id: str
    target: str
    generated_at: str
    verdict_headline: str
    verdict_highest_severity: str | None
    verdict_action_required: bool
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    executive_score: float = 0.0
    # Phase 2C Step 2, Addition B: which formula executive_score was
    # actually computed under, so callers building cross-report views
    # (e.g. GenerateReport._with_history's trend chart) can tell which
    # scores are directly comparable to each other, same reasoning as
    # Report.score_version itself.
    score_version: str = "v2"
    format: str = "pdf"
    file_size: int = 0


class ReportRepository(ABC):
    """Persists and retrieves generated :class:`Report` snapshots."""

    @abstractmethod
    def save(self, report: Report) -> None:
        """Store the report (keyed by its assessment id)."""

    @abstractmethod
    def get(self, assessment_id: AssessmentId) -> Report:
        """Return the report for the assessment, or raise ReportNotFoundError."""

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "generated_at",
        order_dir: str = "desc",
        search: str | None = None,
        severity: str | None = None,
        target: str | None = None,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[list[ReportProjection], int]:
        """Return paginated report projections with total count.

        Unless ``is_admin`` is True, results are restricted to reports
        whose assessment is owned by ``requesting_user``.

        Args:
            limit: Maximum number of results.
            offset: Number of results to skip.
            order_by: Sort column (generated_at, target, verdict_highest_severity, total_findings).
            order_dir: Sort direction (asc, desc).
            search: Free-text search on target.
            severity: Filter by verdict_highest_severity.
            target: Filter by exact target match.
        """

    @abstractmethod
    def count(self) -> int:
        """Return total number of reports."""


# ---------------------------------------------------------------------------
# ScanRepositoryPort  — raw scan results from a single plugin execution
# ---------------------------------------------------------------------------


class ScanRepositoryPort(ABC):
    """Persists and retrieves raw :class:`ScannerResult` objects."""

    @abstractmethod
    def save(self, scan_id: str, result: ScannerResult) -> None:
        """Store a scan result keyed by *scan_id*."""

    @abstractmethod
    def get(self, scan_id: str) -> ScannerResult:
        """Return the scan result for *scan_id*.

        Raises:
            AssessmentNotFoundError: If no scan exists with that id.
        """

    @abstractmethod
    def exists(self, scan_id: str) -> bool:
        """Return True if a scan with *scan_id* is stored."""

    @abstractmethod
    def delete(self, scan_id: str) -> None:
        """Remove a stored scan result.

        Raises:
            AssessmentNotFoundError: If no scan exists with that id.
        """


# ---------------------------------------------------------------------------
# JobRepositoryPort  — scan job metadata (as opposed to scan *results*)
# ---------------------------------------------------------------------------


class JobRepositoryPort(ABC):
    """Persists and retrieves :class:`ScanJob` records."""

    @abstractmethod
    def save(self, job: ScanJob) -> None:
        """Insert or update a scan job (upsert by job id)."""

    @abstractmethod
    def get(self, job_id: str) -> ScanJob:
        """Return the job for *job_id*.

        Raises:
            JobNotFoundError: If no job exists with that id.
        """

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ScanJob]:
        """Return jobs ordered by created_at DESC with pagination."""

    @abstractmethod
    def exists(self, job_id: str) -> bool:
        """Return True if a job with *job_id* is stored."""


# ---------------------------------------------------------------------------
# AssetRepositoryPort  — discovered assets (targets the system knows about)
# ---------------------------------------------------------------------------


class AssetRepositoryPort(ABC):
    """Persists and retrieves discovered :class:`Asset` records."""

    @abstractmethod
    def add(self, asset: Asset) -> None:
        """Insert a new asset (no upsert — use ``update`` to modify)."""

    @abstractmethod
    def get(self, asset_id: str) -> Asset:
        """Return the asset for *asset_id*.

        Raises:
            AssessmentNotFoundError: If no asset exists with that id.
        """

    @abstractmethod
    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Asset]:
        """Return assets ordered by discovered_at DESC with pagination."""

    @abstractmethod
    def exists(self, asset_id: str) -> bool:
        """Return True if an asset with *asset_id* is stored."""
