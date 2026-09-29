"""HTTP API for deterministic Cisco configuration audits."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.services import AuditService


class CiscoAuditRequest(BaseModel):
    configuration: str = Field(..., min_length=1)


router = APIRouter(prefix="/audit", tags=["audit"])


@router.post("/cisco")
def audit_cisco(request: CiscoAuditRequest):
    try:
        return AuditService().audit_cisco_config(request.configuration)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
