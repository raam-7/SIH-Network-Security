import type { AuditReport } from "../../lib/types";
import { calculateSeverityDistribution } from "../../lib/severity-distribution";
import FindingList from "./FindingList";
import AttackScenarios from "./AttackScenarios";

export default function ReportView({
  report,
  auditId,
}: {
  report: AuditReport;
  auditId?: string;
}) {
  const { summary, posture } = report;

  const distribution = calculateSeverityDistribution(report.findings);

  const totalFindings = report.findings.length;

  const deductions =
    posture?.deductions?.reduce(
      (total, item) => total + item.deduction,
      0
    ) ?? 0;

  const scenarios = report.attack_scenarios ?? [];

  return (
    <section className="report-view">

      {/* =====================================================
          SECURITY POSTURE
          ===================================================== */}

      {posture && (
        <section className="posture-dashboard">

          <div className="posture-main">

            <div>
              <span className="eyebrow">
                SECURITY POSTURE SCORE
              </span>

              <div className="posture-score">
                {posture.score}
                <small>/100</small>
              </div>

              <div className="posture-rating">
                <span
                  className={`posture-dot ${
                    posture.score >= 80
                      ? "good"
                      : posture.score >= 60
                      ? "medium"
                      : "risk"
                  }`}
                />

                {posture.rating}
              </div>

              <p>
                Backend-calculated deterministic security score
                based on evaluated compliance controls.
              </p>
            </div>


            <div className="posture-visual">

              <div
                className="score-circle"
                style={{
                  ["--score-progress" as string]:
                    `${posture.score}%`,
                }}
              >
                <strong>{posture.score}</strong>
                <span>Security<br />Score</span>
              </div>

            </div>

          </div>


          {/* POSTURE METRICS */}

          <div className="posture-metrics">

            <div className="posture-metric passed">
              <span className="posture-metric-icon">✓</span>

              <div>
                <small>Passed</small>
                <strong>{posture.passed}</strong>
              </div>
            </div>


            <div className="posture-metric failed">
              <span className="posture-metric-icon">!</span>

              <div>
                <small>Failed</small>
                <strong>{posture.failed}</strong>
              </div>
            </div>


            <div className="posture-metric manual">
              <span className="posture-metric-icon">◷</span>

              <div>
                <small>Manual Review</small>
                <strong>{posture.manual}</strong>
              </div>
            </div>


            <div className="posture-metric deduction">
              <span className="posture-metric-icon">−</span>

              <div>
                <small>Deductions</small>
                <strong>{deductions}</strong>
              </div>
            </div>

          </div>


          {/* EXPLANATION */}

          <div className="posture-explanation">
            <div>
              <span className="explanation-icon">i</span>

              <div>
                <strong>How this score was calculated</strong>

                <p>
                  {posture.explanation}
                </p>
              </div>
            </div>
          </div>


          {/* DEDUCTIONS */}

          {posture.deductions.length > 0 && (
            <div className="deduction-section">

              <div className="subsection-heading">
                <div>
                  <span className="eyebrow">
                    SCORE IMPACT
                  </span>

                  <h3>Security deductions</h3>
                </div>

                <span>
                  {posture.deductions.length} controls
                </span>
              </div>


              <div className="deduction-list">

                {posture.deductions.map((item) => (
                  <div
                    className="deduction-item"
                    key={`${item.rule_id}-${item.deduction}`}
                  >

                    <div className="deduction-rule">
                      {item.rule_id}
                    </div>

                    <div className="deduction-severity">
                      <span
                        className={`severity-badge ${item.severity.toLowerCase()}`}
                      >
                        {item.severity}
                      </span>
                    </div>

                    <strong className="deduction-value">
                      −{item.deduction}
                    </strong>

                  </div>
                ))}

              </div>

            </div>
          )}

        </section>
      )}


      {/* =====================================================
          AUDIT SUMMARY
          ===================================================== */}

      <section className="audit-summary-card">

        <div className="audit-summary-header">

          <div>
            <span className="eyebrow">
              AUDIT SUMMARY
            </span>

            <h2>Compliance assessment</h2>

            <p>
              Deterministic compliance results generated from the
              evaluated network configuration.
            </p>
          </div>


          <div
            className={`overall-status ${summary.overall_status.toLowerCase()}`}
          >
            <span className="status-dot" />
            {summary.overall_status.replace("_", " ")}
          </div>

        </div>


        {/* MAIN COUNTERS */}

        <div className="summary-metrics">

          <div className="summary-metric">
            <span className="summary-metric-icon neutral">
              #
            </span>

            <div>
              <small>Total Controls</small>
              <strong>{summary.total_controls}</strong>
            </div>
          </div>


          <div className="summary-metric">
            <span className="summary-metric-icon success">
              ✓
            </span>

            <div>
              <small>Passed</small>
              <strong>{summary.passed}</strong>
            </div>
          </div>


          <div className="summary-metric">
            <span className="summary-metric-icon danger">
              !
            </span>

            <div>
              <small>Failed</small>
              <strong>{summary.failed}</strong>
            </div>
          </div>


          <div className="summary-metric">
            <span className="summary-metric-icon warning">
              ◷
            </span>

            <div>
              <small>Manual Review</small>
              <strong>{summary.manual}</strong>
            </div>
          </div>

        </div>


        {/* SEVERITY */}

        <div className="severity-section">

          <div className="subsection-heading">
            <div>
              <span className="eyebrow">
                FINDING SEVERITY
              </span>

              <h3>Risk distribution</h3>
            </div>

            <span>{totalFindings} findings</span>
          </div>


          <div className="severity-grid">

            {[
              ["Critical", String(distribution.CRITICAL), "critical"],
              ["High", String(distribution.HIGH), "high"],
              ["Medium", String(distribution.MEDIUM), "medium"],
              ["Low", String(distribution.LOW), "low"],
            ].map(([label, value, level]) => {

              const numericValue = Number(value);

              const percentage =
                totalFindings > 0
                  ? (numericValue / totalFindings) * 100
                  : 0;

              return (
                <div
                  className="severity-card"
                  key={label}
                >

                  <div className="severity-card-top">
                    <span
                      className={`severity-dot ${level}`}
                    />

                    <span>{label}</span>

                    <strong>{numericValue}</strong>
                  </div>

                  <div className="severity-bar">
                    <span
                      className={level}
                      style={{
                        width: `${percentage}%`,
                      }}
                    />
                  </div>

                </div>
              );
            })}

          </div>

        </div>


        <div className="architecture-note">
          <span>✓</span>

          <p>
            Semantic interpretation assists configuration
            normalization. Deterministic rules make the final
            compliance decisions.
          </p>
        </div>

      </section>


      {/* =====================================================
          ATTACK SCENARIOS
          ===================================================== */}

      {scenarios.length > 0 && (
        <section className="report-section">

          <div className="report-section-header">

            <div>
              <span className="eyebrow">
                DEFENSIVE ANALYSIS
              </span>

              <h2>Attack scenarios</h2>

              <p>
                Configuration-driven attack paths identified from
                the evaluated security findings.
              </p>
            </div>

            <span className="section-count">
              {scenarios.length} scenarios
            </span>

          </div>

          <AttackScenarios scenarios={scenarios} />

        </section>
      )}


      {/* =====================================================
          FINDINGS
          ===================================================== */}

      <section className="report-section">

        <div className="report-section-header">

          <div>
            <span className="eyebrow">
              CONTROL ASSESSMENT
            </span>

            <h2>Security findings</h2>

            <p>
              Individual compliance controls evaluated against
              the submitted configuration.
            </p>
          </div>

          <span className="section-count">
            {totalFindings} controls
          </span>

        </div>


        <FindingList
          findings={report.findings}
          auditId={auditId}
        />

      </section>

    </section>
  );
}
