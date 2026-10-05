import assert from "node:assert/strict";
import test from "node:test";
import { calculateSeverityDistribution } from "./severity-distribution";
import type { AuditReportFinding } from "./types";

function finding(result: AuditReportFinding["result"], severity: AuditReportFinding["severity"]): AuditReportFinding {
  return { rule_id: `${severity}-${result}`, result, severity, observed_value: null, expected_value: null, evidence: { line_start: 1, line_end: 1, exact_text: "" }, title: "test", description: "test", remediation: null, risk_level: severity, is_actionable: false, remediation_mode: "NONE", rationale: "test", evidence_score: 0, evidence_type: "test" };
}

test("includes MANUAL findings in severity distribution", () => {
  assert.equal(calculateSeverityDistribution([finding("MANUAL", "MEDIUM"), finding("MANUAL", "MEDIUM")]).MEDIUM, 2);
});

test("counts PASS and FAIL findings by backend severity", () => {
  const counts = calculateSeverityDistribution([finding("FAIL", "HIGH"), finding("FAIL", "MEDIUM"), finding("PASS", "LOW")]);
  assert.deepEqual({ critical: counts.CRITICAL, high: counts.HIGH, medium: counts.MEDIUM, low: counts.LOW }, { critical: 0, high: 1, medium: 1, low: 1 });
});

test("returns zero counts when there are no findings", () => {
  assert.deepEqual(calculateSeverityDistribution([]), { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
});
