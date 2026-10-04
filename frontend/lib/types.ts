export type OverallStatus = "COMPLIANT" | "NON_COMPLIANT" | "REVIEW_REQUIRED";
export type FindingResult = "PASS" | "FAIL" | "MANUAL";
export type FindingSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RemediationMode = "COMMAND" | "MANUAL" | "NONE";
export type RemediationStatus = "AVAILABLE" | "NOT_REQUIRED" | "HUMAN_REVIEW";
export interface RemediationPlan {
  status: RemediationStatus; rule_id: string; vendor: string; title: string;
  recommended_action: string; configuration: string | null; verification: string;
  rationale: string; safety_notes: string[]; source: string;
}
export type HumanReviewStatus = "PENDING" | "REVIEWED";
export type HumanReviewDecision = "COMPLIANT" | "NON_COMPLIANT";
export interface HumanReview { review_id: string; rule_id: string; original_result: "MANUAL"; decision: HumanReviewDecision; reviewer: string; reviewer_reason: string; status: HumanReviewStatus; }

export interface Evidence { line_start: number; line_end: number; exact_text: string; }
export type AttackScenarioStatus = "APPLICABLE" | "POTENTIAL" | "NOT_APPLICABLE";
export interface AttackScenario { scenario_id: string; name: string; description: string; status: AttackScenarioStatus; severity: FindingSeverity; supporting_rule_ids: string[]; evidence: Evidence[]; evidence_score: number; entry_point: string; potential_path: string[]; potential_impact: string; recommended_controls: string[]; requires_human_review: boolean; }
export interface AuditSummary {
  total_controls: number; passed: number; failed: number; manual: number;
  informational: number; overall_status: OverallStatus;
  critical_count: number; high_count: number; medium_count: number; low_count: number;
  review_pending_count: number; review_completed_count: number;
}
export interface AuditReportFinding {
  rule_id: string; result: FindingResult; severity: FindingSeverity;
  observed_value: unknown; expected_value: unknown; evidence: Evidence;
  title: string; description: string; remediation: string | null;
  remediation_plan?: RemediationPlan | null;
  risk_level: string; is_actionable: boolean; remediation_mode: RemediationMode;
  rationale: string; evidence_score: number; evidence_type: string;
  semantic_concept?: string | null; semantic_property?: string | null; semantic_value?: unknown;
  ai_confidence?: number | null; mapping_source?: string | null;
  review?: HumanReview | null;
  explanation?: FindingExplanation | null;
}
export interface FindingExplanation { explanation: string; detected_condition: string; expected_condition: string; evidence_summary: string; explanation_confidence: number; source: string; }
export interface PostureDeduction { rule_id: string; severity: FindingSeverity; deduction: number; reason: string; }
export interface PostureScore { score: number; rating: string; total_controls: number; passed: number; failed: number; manual: number; deductions: PostureDeduction[]; explanation: string; }
export interface AuditReport {
  vendor: string; platform: string; summary: AuditSummary;
  findings: AuditReportFinding[]; parsed_command_count: number;
  security_fact_count: number; configuration_hash: string | null;
  attack_scenarios: AttackScenario[];
  posture?: PostureScore | null;
}
export interface AuditHistorySummary {
  audit_id: string; vendor: string; platform: string; overall_status: OverallStatus;
  total_controls: number; passed: number; failed: number; manual: number;
  informational: number; parsed_command_count: number; security_fact_count: number;
  created_at: string;
}
export interface AuditHistoryResponse {
  items: AuditHistorySummary[];
  pagination: { limit: number; offset: number; total: number; has_more: boolean };
}
