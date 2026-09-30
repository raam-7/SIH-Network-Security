"""Lightweight audit-history response contract."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from .audit_report import AuditOverallStatus


class AuditHistorySummary(BaseModel):
    audit_id: UUID
    vendor: str
    platform: str
    overall_status: AuditOverallStatus
    total_controls: int
    passed: int
    failed: int
    manual: int
    informational: int
    parsed_command_count: int
    security_fact_count: int
    created_at: datetime
