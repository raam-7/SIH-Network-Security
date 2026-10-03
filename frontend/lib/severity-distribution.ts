import type { AuditReportFinding, FindingSeverity } from "./types";

export function calculateSeverityDistribution(findings: AuditReportFinding[]): Record<FindingSeverity, number> {
  const counts: Record<FindingSeverity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}
