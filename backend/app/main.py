from fastapi import FastAPI

from backend.app.api.audit import router as audit_router
from backend.app.api.human_review import router as human_review_router
from backend.app.api.audits import router as audits_router

app = FastAPI(
    title="SIH Network Security Compliance Auditor",
    version="0.1.0",
)

app.include_router(audit_router, prefix="/api/v1")
app.include_router(human_review_router, prefix="/api/v1")
app.include_router(audits_router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "network-security-compliance",
        "version": "0.1.0",
    }
