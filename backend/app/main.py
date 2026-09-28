from fastapi import FastAPI

app = FastAPI(
    title="SIH Network Security Compliance Auditor",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "network-security-compliance",
        "version": "0.1.0",
    }