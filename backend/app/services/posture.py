from pydantic import BaseModel, Field
from backend.app.schemas import Finding, FindingResult, FindingSeverity

WEIGHTS = {FindingSeverity.CRITICAL: 40, FindingSeverity.HIGH: 25, FindingSeverity.MEDIUM: 10, FindingSeverity.LOW: 5, FindingSeverity.INFO: 0}

class PostureDeduction(BaseModel):
    rule_id: str; severity: FindingSeverity; deduction: int; reason: str

class PostureScore(BaseModel):
    score: int = Field(ge=0, le=100)
    rating: str
    total_controls: int; passed: int; failed: int; manual: int
    deductions: list[PostureDeduction] = []
    explanation: str

def calculate_posture(findings: list[Finding]) -> PostureScore:
    deductions = []
    for finding in findings:
        if finding.result is FindingResult.FAIL:
            deductions.append(PostureDeduction(rule_id=finding.rule_id, severity=finding.severity, deduction=WEIGHTS[finding.severity], reason=finding.title))
        elif finding.result is FindingResult.MANUAL:
            deductions.append(PostureDeduction(rule_id=finding.rule_id, severity=finding.severity, deduction=max(1, WEIGHTS[finding.severity] // 2), reason="Manual verification remains unresolved"))
    score = max(0, min(100, 100 - sum(item.deduction for item in deductions)))
    rating = "strong" if score >= 90 else " guarded" if score >= 70 else "at risk" if score >= 40 else "critical"
    return PostureScore(score=score, rating=rating.strip(), total_controls=len(findings), passed=sum(f.result is FindingResult.PASS for f in findings), failed=sum(f.result is FindingResult.FAIL for f in findings), manual=sum(f.result is FindingResult.MANUAL for f in findings), deductions=deductions, explanation="Score starts at 100; failed controls deduct their documented severity weight and MANUAL controls deduct half weight until reviewed.")
