# SIH Network Security Compliance Auditor

An AI-augmented network security configuration compliance platform for SIH Round 2. The platform is designed to analyze network configurations while keeping compliance decisions deterministic, explainable, and auditable.

## Objective

Analyze Cisco IOS/IOS-XE, Juniper Junos, and Fortinet FortiGate configurations; normalize vendor-specific syntax into canonical security facts; evaluate versioned compliance rules; and produce evidence, risk, and remediation guidance.

The AI/LLM layer may assist with semantic interpretation, retrieval, explanations, and unknown-syntax proposals. It must never be the final authority for compliance. Final PASS, FAIL, or MANUAL decisions come from deterministic rules.

## MVP scope

The current MVP foundation is a FastAPI backend with a health endpoint. Cisco IOS/IOS-XE is the first implementation target. Parsing, normalization, compliance controls, evidence, remediation, and dashboard/report features will be added incrementally.

Supported vendors in the planned platform:

- Cisco IOS/IOS-XE — first implementation target
- Juniper Junos — planned
- Fortinet FortiGate — planned

## System architecture

```text
Configuration File / Read-only SSH
        ↓
Vendor Detection → Configuration Parsing → Semantic Normalization
        ↓
Canonical Security Facts → Deterministic Compliance Rules
        ↓
PASS / FAIL / MANUAL → Evidence + Risk → Remediation
        ↓
Dashboard / Report
```

## Current development status

- FastAPI backend is operational, with `/health` and Swagger documentation available.
- Cisco IOS/IOS-XE parsing, deterministic compliance, evidence, risk/remediation, reporting, and PostgreSQL audit persistence are implemented.
- The audit-history API provides lightweight paginated summaries and complete persisted report retrieval.
- Juniper and Fortinet support are planned.
- AI/RAG components are limited to the project’s existing assistive/prototype scope; they are not the final compliance authority and full production AI integration is not claimed.
- pgvector and complete CIS/NIST framework coverage are not implemented or claimed.

### Prototype compliance scope

The project currently provides a limited prototype compliance control set; it does not claim complete CIS, NIST, or Cisco benchmark coverage. CIS metadata is used for concrete prototype configuration requirements, Cisco documentation supports configuration semantics, and NIST CSF is represented only as contextual framework mapping. Unverified framework metadata remains explicitly marked, and test configurations are not authoritative security baselines.

## Technology stack

- Python 3.11+
- FastAPI
- Uvicorn
- Planned frontend and analysis components will be introduced as the MVP evolves.

## Local setup

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Keep `.env` local. Never commit credentials, API keys, passwords, or private SSH material.

## Start the backend

```powershell
\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`.

- Swagger UI: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

## Repository structure

```text
backend/          FastAPI application
collectors/       Future file and read-only SSH collectors
parsers/          Vendor configuration parsers
compliance/       Deterministic compliance rules
ai/               AI-assisted interpretation and explanation
knowledge_base/   Future security knowledge and references
frontend/         Future dashboard
tests/            Automated tests
docs/             Project documentation
examples/         Safe sample configurations
training/         Future model-training assets (local/generated files ignored)
docker/           Container-related files
```

## Development workflow

1. Create a focused branch from `main`.
2. Make the smallest scoped change and add tests where applicable.
3. Run the backend and verify `/health` and `/docs`.
4. Review `git diff` and `git status`; confirm no secrets or generated files are staged.
5. Open a pull request for review.

Suggested branch names are `feature/<short-name>`, `fix/<short-name>`, and `docs/<short-name>`.

## GitHub collaboration

The GitHub repository should be created as **Private**. Do not push directly to `main`; use private branches and pull requests. Never commit `.env`, credentials, device configuration containing secrets, model weights, checkpoints, uploads, or runtime artifacts.
