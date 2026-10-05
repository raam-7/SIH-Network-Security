from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.api.audit import CiscoAuditRequest, VendorAuditRequest
from backend.app.db import get_session
from backend.app.schemas.audit_history import AuditHistoryPagination, AuditHistoryResponse
from backend.app.schemas.audit_report import AuditOverallStatus
from backend.app.services import AuditReportService, AuditService
from backend.app.services.audit import hash_configuration
from backend.app.services.audit_repository import AuditRepository

router = APIRouter(prefix="/audits", tags=["audits"])


@router.post("")
def create_audit(request: CiscoAuditRequest, session: Session = Depends(get_session)):
    try:
        report = AuditReportService().build_report(AuditService().audit_cisco_config(request.configuration))
        report.configuration_hash = hash_configuration(request.configuration)
        audit_id = AuditRepository(session).save_report(report)
        return {"audit_id": str(audit_id), "report": report}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/vendor")
def create_vendor_audit(request: VendorAuditRequest, session: Session = Depends(get_session)):
    try:
        report = AuditReportService().build_report(AuditService().audit_config(request.vendor, request.configuration))
        report.configuration_hash = hash_configuration(request.configuration)
        audit_id = AuditRepository(session).save_report(report)
        return {"audit_id": str(audit_id), "report": report}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{audit_id}")
def get_audit(audit_id: UUID, session: Session = Depends(get_session)):
    report = AuditRepository(session).get_report(audit_id)
    if report is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return report


@router.get("", response_model=AuditHistoryResponse)
def list_audits(
    limit: int = 50,
    offset: int = 0,
    vendor: str | None = None,
    platform: str | None = None,
    overall_status: AuditOverallStatus | None = None,
    session: Session = Depends(get_session),
):
    if limit < 1 or limit > 100 or offset < 0:
        raise HTTPException(status_code=422, detail="invalid pagination")
    items, total = AuditRepository(session).list_summaries(
        limit=limit,
        offset=offset,
        vendor=vendor,
        platform=platform,
        overall_status=overall_status,
    )
    return AuditHistoryResponse(
        items=items,
        pagination=AuditHistoryPagination(
            limit=limit,
            offset=offset,
            total=total,
            has_more=offset + len(items) < total,
        ),
    )
