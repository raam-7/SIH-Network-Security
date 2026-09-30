"""HTTP API for deterministic Cisco configuration audits."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.schemas.audit_report import AuditReport
from backend.app.services import AuditReportService, AuditService


class CiscoAuditRequest(BaseModel):
    configuration: str = Field(..., min_length=1)


router = APIRouter(prefix="/audit", tags=["audit"])


@router.post("/cisco")
def audit_cisco(request: CiscoAuditRequest):
    try:
        return AuditService().audit_cisco_config(request.configuration)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cisco/report", response_model=AuditReport)
def audit_cisco_report(request: CiscoAuditRequest):
    try:
        result = AuditService().audit_cisco_config(request.configuration)
        return AuditReportService().build_report(result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
