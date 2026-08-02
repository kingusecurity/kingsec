"""Typed identifiers.

Why wrap a string in a type instead of passing raw ``str`` around?
    Type safety. A function that expects an ``AssessmentId`` cannot be handed a
    ``FindingId`` (or an arbitrary string) by mistake — the type checker and the
    reader both catch it. It also gives the id a domain-meaningful name and a
    single place to enforce "ids are never empty".

Both are frozen dataclasses, so they are immutable and compare by value: two
``AssessmentId`` with the same string are equal and hash the same, which is what
we want for using them as dictionary keys.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from ._validation import ensure_non_empty


@dataclass(frozen=True, slots=True)
class AssessmentId:
    """Unique identifier for an :class:`Assessment`."""

    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "AssessmentId")

    @classmethod
    def generate(cls) -> AssessmentId:
        """Create a fresh, collision-resistant id (prefixed for readability)."""
        return cls(f"asmt-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class FindingId:
    """Unique identifier for a :class:`Finding`."""

    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "FindingId")

    @classmethod
    def generate(cls) -> FindingId:
        return cls(f"find-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ScanId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "ScanId")

    @classmethod
    def generate(cls) -> ScanId:
        return cls(f"scan-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AssetId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "AssetId")

    @classmethod
    def generate(cls) -> AssetId:
        return cls(f"ast-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ComplianceFrameworkId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "ComplianceFrameworkId")

    @classmethod
    def generate(cls) -> ComplianceFrameworkId:
        return cls(f"cfw-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class MappingId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "MappingId")

    @classmethod
    def generate(cls) -> MappingId:
        return cls(f"map-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ReportId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "ReportId")

    @classmethod
    def generate(cls) -> ReportId:
        return cls(f"rpt-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ScheduleId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "ScheduleId")

    @classmethod
    def generate(cls) -> ScheduleId:
        return cls(f"sch-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class MonitorEventId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "MonitorEventId")

    @classmethod
    def generate(cls) -> MonitorEventId:
        return cls(f"evt-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AlertId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "AlertId")

    @classmethod
    def generate(cls) -> AlertId:
        return cls(f"alrt-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RuleId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "RuleId")

    @classmethod
    def generate(cls) -> RuleId:
        return cls(f"rule-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CveId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "CveId")

    @classmethod
    def generate(cls) -> CveId:
        return cls(f"cve-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ThreatFeedId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "ThreatFeedId")

    @classmethod
    def generate(cls) -> ThreatFeedId:
        return cls(f"feed-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class KevEntryId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "KevEntryId")

    @classmethod
    def generate(cls) -> KevEntryId:
        return cls(f"kev-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AttackSurfaceId:
    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "AttackSurfaceId")

    @classmethod
    def generate(cls) -> AttackSurfaceId:
        return cls(f"expo-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value
