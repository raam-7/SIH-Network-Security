from fastapi import FastAPI

from backend.app.api.audit import router as audit_router

app = FastAPI(
    title="SIH Network Security Compliance Auditor",
    version="0.1.0",
)

app.include_router(audit_router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "network-security-compliance",
        "version": "0.1.0",
    }
