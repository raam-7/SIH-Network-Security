import type { AttackScenario } from "../../lib/types";

export default function AttackScenarios({
  scenarios,
}: {
  scenarios: AttackScenario[];
}) {
  if (!scenarios.length) {
    return (
      <div className="attack-empty">
        <div className="attack-empty-icon">✓</div>
        <strong>No attack scenarios identified</strong>
        <p>No configuration-driven attack paths were generated for this audit.</p>
      </div>
    );
  }

  return (
    <div className="attack-scenario-grid">
      {scenarios.map((scenario, index) => (
        <article className="attack-modern-card" key={scenario.scenario_id}>
          <div className="attack-modern-header">
            <div className="attack-number">
              {String(index + 1).padStart(2, "0")}
            </div>

            <div className="attack-title">
              <span>ATTACK SCENARIO</span>
              <h3>{scenario.name}</h3>
            </div>

            <span className={`severity-badge ${scenario.severity.toLowerCase()}`}>
              {scenario.severity}
            </span>
          </div>

          <div className="attack-modern-body">
            <div className="attack-status-row">
              <span className={`attack-status ${scenario.status.toLowerCase()}`}>
                {scenario.status.replace("_", " ")}
              </span>

              {scenario.requires_human_review && (
                <span className="attack-review-badge">
                  Human review
                </span>
              )}
            </div>

            <p className="attack-description">
              {scenario.description}
            </p>

            {scenario.entry_point && (
              <div className="attack-detail-block">
                <span className="attack-section-label">ENTRY POINT</span>
                <p>{scenario.entry_point}</p>
              </div>
            )}

            {scenario.potential_path.length > 0 && (
              <div className="attack-path-section">
                <span className="attack-section-label">
                  POTENTIAL ATTACK PATH
                </span>

                <div className="attack-modern-path">
                  {scenario.potential_path.map((step: string, stepIndex: number) => (
                    <div
                      className="attack-path-step"
                      key={`${step}-${stepIndex}`}
                    >
                      <span>{stepIndex + 1}</span>
                      <strong>{step}</strong>

                      {stepIndex < scenario.potential_path.length - 1 && (
                        <i>→</i>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="attack-detail-block">
              <span className="attack-section-label">
                POTENTIAL IMPACT
              </span>
              <p>{scenario.potential_impact}</p>
            </div>

            {scenario.recommended_controls.length > 0 && (
              <div className="attack-mitigation">
                <span className="mitigation-icon">✓</span>

                <div>
                  <strong>Recommended controls</strong>

                  <ul>
                    {scenario.recommended_controls.map(
                      (control: string, controlIndex: number) => (
                        <li key={`${control}-${controlIndex}`}>
                          {control}
                        </li>
                      )
                    )}
                  </ul>
                </div>
              </div>
            )}

            {scenario.evidence.length > 0 && (
              <div className="attack-evidence">
                <span className="attack-section-label">
                  SUPPORTING EVIDENCE
                </span>

                {scenario.evidence.map((evidence, evidenceIndex) => (
                  <div
                    className="attack-evidence-item"
                    key={`${evidence.line_start}-${evidenceIndex}`}
                  >
                    <code>
                      Lines {evidence.line_start} – {evidence.line_end}
                    </code>

                    <p>{evidence.exact_text}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="attack-modern-footer">
            <span>
              Supporting controls: {scenario.supporting_rule_ids.length}
            </span>

            <span>
              Evidence score: {scenario.evidence_score}
            </span>
          </div>
        </article>
      ))}
    </div>
  );
}
