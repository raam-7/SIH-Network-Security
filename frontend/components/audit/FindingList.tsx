import type { AuditReportFinding } from "../../lib/types";

export default function FindingList({
  findings,
  auditId,
}: {
  findings: AuditReportFinding[];
  auditId?: string;
}) {
  if (!findings.length) {
    return (
      <div className="findings-empty">
        <div className="findings-empty-icon">✓</div>
        <strong>No security findings</strong>
        <p>No compliance findings were generated for this audit.</p>
      </div>
    );
  }

  return (
    <div className="findings-container">
      {findings.map((finding, index) => (
        <article
          className="finding-modern-card"
          key={`${finding.rule_id}-${index}`}
        >
          <div className="finding-modern-header">
            <div className="finding-title-area">
              <div className="finding-number">
                {String(index + 1).padStart(2, "0")}
              </div>

              <div>
                <span className="finding-control-id">
                  {finding.rule_id}
                </span>

                <h3>{finding.title}</h3>
              </div>
            </div>

            <div className="finding-badges">
              <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                {finding.severity}
              </span>

              <span className={`finding-status ${finding.result.toLowerCase()}`}>
                {finding.result}
              </span>
            </div>
          </div>

          <div className="finding-modern-body">
            <div className="finding-description">
              <span className="finding-section-label">FINDING</span>
              <p>{finding.description}</p>
            </div>

            <div className="finding-grid">
              <div className="finding-detail-box">
                <span>EVIDENCE</span>
                <p>
                  {finding.evidence.exact_text ||
                    "Evidence recorded by audit engine."}
                </p>
              </div>

              <div className="finding-detail-box">
                <span>RECOMMENDATION</span>
                <p>
                  {finding.remediation ||
                    finding.remediation_plan?.recommended_action ||
                    "Review the associated security control."}
                </p>
              </div>
            </div>

            <div className="finding-location">
              <span>CONFIGURATION LOCATION</span>

              <code>
                Lines {finding.evidence.line_start} –{" "}
                {finding.evidence.line_end}
              </code>
            </div>

            {finding.explanation && (
              <div className="finding-ai-explanation">
                <span className="finding-section-label">
                  AI EXPLANATION
                </span>

                <p>{finding.explanation.explanation}</p>
              </div>
            )}
          </div>

          <div className="finding-modern-footer">
            <span>Control evaluation #{index + 1}</span>
            <span>Risk: {finding.risk_level}</span>

            {auditId && (
              <span className="finding-audit-ref">
                Audit: {auditId.slice(0, 8)}…
              </span>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}
