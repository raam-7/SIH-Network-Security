from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Boolean, Uuid

from backend.app.db.base import Base


class AuditORM(Base):
    __tablename__ = "audits"
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    vendor: Mapped[str] = mapped_column(String(64))
    platform: Mapped[str] = mapped_column(String(64))
    overall_status: Mapped[str] = mapped_column(String(32))
    total_controls: Mapped[int] = mapped_column(Integer)
    passed: Mapped[int] = mapped_column(Integer)
    failed: Mapped[int] = mapped_column(Integer)
    manual: Mapped[int] = mapped_column(Integer)
    informational: Mapped[int] = mapped_column(Integer)
    parsed_command_count: Mapped[int] = mapped_column(Integer)
    security_fact_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    configuration_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    findings: Mapped[list[FindingORM]] = relationship(back_populates="audit", cascade="all, delete-orphan", order_by="FindingORM.sequence")
    reviews: Mapped[list[HumanReviewORM]] = relationship(back_populates="audit", cascade="all, delete-orphan")


class FindingORM(Base):
    __tablename__ = "findings"
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    rule_id: Mapped[str] = mapped_column(String(128))
    result: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(32))
    observed_value: Mapped[object | None] = mapped_column(JSON, nullable=True)
    expected_value: Mapped[object | None] = mapped_column(JSON, nullable=True)
    evidence_line_start: Mapped[int] = mapped_column(Integer)
    evidence_line_end: Mapped[int] = mapped_column(Integer)
    evidence_exact_text: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(32))
    is_actionable: Mapped[bool] = mapped_column(Boolean)
    remediation_mode: Mapped[str] = mapped_column(String(32))
    rationale: Mapped[str] = mapped_column(Text)
    evidence_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    semantic_concept: Mapped[str | None] = mapped_column(String(128), nullable=True)
    semantic_property: Mapped[str | None] = mapped_column(String(128), nullable=True)
    semantic_value: Mapped[object | None] = mapped_column(JSON, nullable=True)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    mapping_source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    audit: Mapped[AuditORM] = relationship(back_populates="findings")
    risk_assessment: Mapped[RiskAssessmentORM | None] = relationship(back_populates="finding", cascade="all, delete-orphan", uselist=False)


class RiskAssessmentORM(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(128))
    result: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(32))
    risk_level: Mapped[str] = mapped_column(String(32))
    is_actionable: Mapped[bool] = mapped_column(Boolean)
    rationale: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_mode: Mapped[str] = mapped_column(String(32))
    finding: Mapped[FindingORM] = relationship(back_populates="risk_assessment")


class HumanReviewORM(Base):
    __tablename__ = "human_reviews"
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(128))
    original_result: Mapped[str] = mapped_column(String(32))
    decision: Mapped[str] = mapped_column(String(32))
    reviewer: Mapped[str] = mapped_column(String(255))
    reviewer_reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="REVIEWED")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    audit: Mapped[AuditORM] = relationship(back_populates="reviews")
    finding: Mapped[FindingORM] = relationship()
