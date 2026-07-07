"""SQLAlchemy ORM models for KingSec persistence.

These classes are the DATABASE representation only. They are deliberately kept
separate from the pure domain entities (Data Mapper pattern): the domain never
imports SQLAlchemy, and these models never carry business rules. A dedicated
mapping layer (``mappers.py``) translates between the two worlds.

Storage decisions worth noting:
    * Timestamps are stored as ISO-8601 strings. SQLite has no native
      timezone-aware datetime type, and the domain requires tz-aware timestamps,
      so storing the ISO string round-trips the timezone losslessly.
    * Enums are stored by their ``name`` (e.g. "CRITICAL", "RUNNING") for
      readability when inspecting the database directly.
    * A ``Report`` is an immutable snapshot (a document), so its finding entries
      and severity counts are stored as JSON rather than normalised tables.
    * Child collections use ``cascade="all, delete-orphan"`` so removing an
      aggregate removes its children in one operation.
"""

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.types import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all KingSec ORM models."""


class AssessmentORM(Base):
    """Row representation of an :class:`~kingsec.domain.Assessment` aggregate."""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target_value: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    # Authorization is optional (an assessment may be DRAFT / unauthorized).
    authorized_by: Mapped[str | None] = mapped_column(String, nullable=True)
    authorized_at: Mapped[str | None] = mapped_column(String, nullable=True)
    authorization_scope: Mapped[str | None] = mapped_column(String, nullable=True)

    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings: Mapped[list["FindingORM"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",  # avoid N+1: load all findings in one extra query
    )


class FindingORM(Base):
    """Row representation of a :class:`~kingsec.domain.Finding` entity."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    discovered_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    assessment: Mapped[AssessmentORM] = relationship(back_populates="findings")
    evidence: Mapped[list["EvidenceORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )
    recommendations: Mapped[list["RecommendationORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )


class EvidenceORM(Base):
    """Row representation of an :class:`~kingsec.domain.Evidence` value object.

    Evidence has no domain identity, so it gets a surrogate autoincrement PK
    purely for the database.
    """

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    summary: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    collected_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    finding: Mapped[FindingORM] = relationship(back_populates="evidence")


class RecommendationORM(Base):
    """Row representation of a :class:`~kingsec.domain.Recommendation` value object."""

    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String, nullable=False)

    finding: Mapped[FindingORM] = relationship(back_populates="recommendations")


class ReportORM(Base):
    """Row representation of a :class:`~kingsec.domain.Report` snapshot.

    One report per assessment, so the assessment id is the primary key. The
    verdict is stored as queryable columns; the finding entries and severity
    counts are stored as JSON because a report is an immutable document.
    """

    __tablename__ = "reports"

    assessment_id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    generated_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    verdict_headline: Mapped[str] = mapped_column(String, nullable=False)
    verdict_action_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verdict_highest_severity: Mapped[str | None] = mapped_column(String, nullable=True)

    # entries: list of dicts; severity_counts: list of [severity_name, count].
    entries: Mapped[list] = mapped_column(JSON, nullable=False)
    severity_counts: Mapped[list] = mapped_column(JSON, nullable=False)
