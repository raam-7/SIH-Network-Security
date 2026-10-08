import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from backend.app.api.audit import router as audit_router
from backend.app.api.human_review import router as human_review_router
from backend.app.api.audits import router as audits_router

app = FastAPI(
    title="SIH Network Security Compliance Auditor",
    version="0.1.0",
)

logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(_request, exc: SQLAlchemyError):
    logger.exception("Database request failed", exc_info=exc)
    return JSONResponse(
        status_code=503,
        content={
            "detail": (
                "Database unavailable. Check that PostgreSQL is running and "
                "DATABASE_URL in the root .env file has valid credentials."
            )
        },
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
