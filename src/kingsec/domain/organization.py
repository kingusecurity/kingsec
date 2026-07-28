from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class OrgRole(StrEnum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


class OrgEventType(StrEnum):
    ASSESSMENT_CREATED = "assessment.created"
    ASSESSMENT_COMPLETED = "assessment.completed"
    REPORT_GENERATED = "report.generated"
    CRITICAL_FINDING = "finding.critical"
    USER_JOINED = "user.joined"
    SCANNER_FAILED = "scanner.failed"
    INTEGRATION_EXECUTED = "integration.executed"


@dataclass(frozen=True)
class OrganizationId:
    value: str

    def __str__(self) -> str:
        return self.value

    @classmethod
    def generate(cls) -> OrganizationId:
        import uuid
        return cls(f"org-{uuid.uuid4().hex}")


@dataclass(frozen=True)
class TeamId:
    value: str

    def __str__(self) -> str:
        return self.value

    @classmethod
    def generate(cls) -> TeamId:
        import uuid
        return cls(f"team-{uuid.uuid4().hex}")


@dataclass
class Organization:
    id: OrganizationId
    name: str
    slug: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class Team:
    id: TeamId
    organization_id: str
    name: str
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class OrganizationMembership:
    user_id: str
    organization_id: str
    role: OrgRole = OrgRole.VIEWER
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class TeamMembership:
    user_id: str
    team_id: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class OrgActivityEvent:
    id: str
    organization_id: str
    event_type: OrgEventType
    actor_id: str
    message: str
    metadata: dict[str, object] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class ReportShare:
    report_id: str
    organization_id: str
    shared_by: str
    shared_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    can_view: bool = True
    can_comment: bool = False
    can_download: bool = False
    can_regenerate: bool = False
