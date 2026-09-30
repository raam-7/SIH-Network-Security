"""Deterministic, explainable evidence quality scoring."""
from backend.app.schemas import Finding

def score_evidence(finding: Finding) -> tuple[int, str]:
    text = finding.evidence.exact_text.strip()
    if not text:
        return 0, "No supporting configuration evidence found."
    if finding.result.value == "PASS" and finding.mapping_source == "deterministic_mapping":
        return 100, "Direct configuration evidence"
    if finding.mapping_source in {"knowledge_base", "kb_mapping"}:
        return 95, "Direct evidence interpreted through the knowledge base"
    if finding.ai_confidence is not None:
        return max(1, min(79, round(finding.ai_confidence * 79))), "Semantic/indirect evidence"
    return 80, "Strong contextual configuration evidence"
