"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import {
  getAudit,
  getAudits,
  userFacingApiError,
} from "../../lib/api";
import type {
  AuditHistoryResponse,
  AuditReport,
} from "../../lib/types";
import AttackScenarios from "../../components/audit/AttackScenarios";

function AttackScenarioWorkspace() {
  const params = useSearchParams();
  const selectedId = params.get("audit_id") || "";

  const [audits, setAudits] =
    useState<AuditHistoryResponse | null>(null);

  const [report, setReport] =
    useState<AuditReport | null>(null);

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void getAudits(15, 0)
      .then(setAudits)
      .catch((err) => setError(userFacingApiError(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (selectedId) {
      void getAudit(selectedId)
        .then(setReport)
        .catch((err) => setError(userFacingApiError(err)));
    } else {
      void Promise.resolve().then(() => setReport(null));
    }
  }, [selectedId]);

  /* =====================================================
     LOADING
     ===================================================== */

  if (loading) {
    return (
      <div className="scenario-page">

        <section className="scenario-page-header">
          <span className="eyebrow">
            DEFENSIVE SECURITY ANALYSIS
          </span>

          <h1>Attack Scenario Analysis</h1>

          <p>
            Loading persisted security assessments...
          </p>
        </section>

        <div className="scenario-loading">
          <div className="loading-spinner" />

          <strong>
            Loading audit repository
          </strong>

          <span>
            Fetching available security assessments.
          </span>
        </div>

      </div>
    );
  }


  /* =====================================================
     ERROR
     ===================================================== */

  if (error) {
    return (
      <div className="scenario-page">

        <section className="scenario-page-header">
          <span className="eyebrow">
            DEFENSIVE SECURITY ANALYSIS
          </span>

          <h1>Attack Scenario Analysis</h1>

          <p>
            We couldn't load the selected security assessment.
          </p>
        </section>

        <div className="scenario-error">

          <div className="scenario-error-icon">
            !
          </div>

          <div>
            <strong>
              Unable to load attack scenarios
            </strong>

            <p>{error}</p>
          </div>

          <Link
            href="/audits"
            className="button"
          >
            Open Audit History
          </Link>

        </div>

      </div>
    );
  }


  /* =====================================================
     SELECTED AUDIT
     ===================================================== */

  if (report) {
    const scenarios = report.attack_scenarios ?? [];

    return (
      <div className="scenario-page">

        <section className="scenario-page-header">

          <div className="scenario-back">
            <Link href="/attack-scenarios">
              ← Select another audit
            </Link>
          </div>

          <div className="scenario-title-row">

            <div>
              <span className="eyebrow">
                DEFENSIVE ANALYSIS
              </span>

              <h1>Attack Scenarios</h1>

              <p>
                Configuration-driven attack paths derived from
                the actual compliance findings of this audit.
              </p>
            </div>

            <Link
              href={`/audits/${selectedId}`}
              className="button"
            >
              View Full Audit →
            </Link>

          </div>

        </section>


        {/* AUDIT CONTEXT */}

        <section className="scenario-context">

          <div className="scenario-context-main">

            <span className="scenario-context-icon">
              ◈
            </span>

            <div>

              <span className="scenario-context-label">
                SELECTED AUDIT
              </span>

              <strong>
                {report.vendor}
                {" · "}
                {report.platform}
              </strong>

              <code>
                {selectedId}
              </code>

            </div>

          </div>


          <div className="scenario-context-stats">

            <div>
              <small>Status</small>

              <strong
                className={
                  report.summary.overall_status ===
                  "COMPLIANT"
                    ? "status-good"
                    : "status-risk"
                }
              >
                {report.summary.overall_status.replace(
                  "_",
                  " "
                )}
              </strong>
            </div>

            <div>
              <small>Failed</small>
              <strong>
                {report.summary.failed}
              </strong>
            </div>

            <div>
              <small>Manual</small>
              <strong>
                {report.summary.manual}
              </strong>
            </div>

            <div>
              <small>Scenarios</small>
              <strong>
                {scenarios.length}
              </strong>
            </div>

          </div>

        </section>


        {/* SAFETY NOTE */}

        <div className="scenario-safety-note">

          <span>✓</span>

          <div>
            <strong>
              Defensive analysis only
            </strong>

            <p>
              These scenarios model potential attack paths
              from configuration weaknesses. NetSentinel does
              not perform exploitation or execute attacks.
            </p>
          </div>

        </div>


        {/* SCENARIOS */}

        {scenarios.length > 0 ? (

          <section className="scenario-results">

            <div className="scenario-results-header">

              <div>
                <span className="eyebrow">
                  CONFIGURATION-DRIVEN ANALYSIS
                </span>

                <h2>
                  Identified attack paths
                </h2>

                <p>
                  Review the potential security impact and
                  recommended defensive mitigations.
                </p>
              </div>

              <span className="section-count">
                {scenarios.length} scenarios
              </span>

            </div>

            <AttackScenarios
              scenarios={scenarios}
            />

          </section>

        ) : (

          <section className="scenario-empty">

            <div className="scenario-empty-icon">
              ✓
            </div>

            <h2>
              No attack scenarios identified
            </h2>

            <p>
              No configuration-driven attack paths were
              generated from this audit's findings.
            </p>

            <Link
              href={`/audits/${selectedId}`}
              className="button primary"
            >
              View Audit Findings →
            </Link>

          </section>

        )}

      </div>
    );
  }


  /* =====================================================
     AUDIT SELECTION
     ===================================================== */

  return (
    <div className="scenario-page">

      <section className="scenario-page-header">

        <span className="eyebrow">
          DEFENSIVE SECURITY ANALYSIS
        </span>

        <h1>
          Attack Scenario Analysis
        </h1>

        <p>
          Select a persisted audit to inspect defensive attack
          paths derived from its actual compliance findings.
        </p>

      </section>


      <div className="scenario-safety-note">

        <span>✓</span>

        <div>
          <strong>
            Configuration-driven defensive modeling
          </strong>

          <p>
            NetSentinel uses the findings produced by the audit
            engine to explain possible attack paths. No
            exploitation is performed.
          </p>
        </div>

      </div>


      {!audits || audits.items.length === 0 ? (

        <section className="scenario-empty">

          <div className="scenario-empty-icon">
            ▤
          </div>

          <h2>
            No persisted audits yet
          </h2>

          <p>
            Run a security audit first. Once an audit is saved,
            its attack scenarios will appear here.
          </p>

          <Link
            href="/"
            className="button primary"
          >
            Start New Audit →
          </Link>

        </section>

      ) : (

        <section className="scenario-audit-list">

          <div className="scenario-results-header">

            <div>
              <span className="eyebrow">
                AUDIT REPOSITORY
              </span>

              <h2>
                Select an audit
              </h2>

              <p>
                Choose an assessment to inspect its potential
                attack paths.
              </p>
            </div>

            <Link
              href="/audits"
              className="button"
            >
              View All Audits
            </Link>

          </div>


          <div className="scenario-audit-cards">

            {audits.items.map((audit) => (

              <article
                className="scenario-audit-card"
                key={audit.audit_id}
              >

                <div className="scenario-audit-card-top">

                  <div className="scenario-vendor-icon">
                    {audit.vendor.charAt(0).toUpperCase()}
                  </div>

                  <div>

                    <strong>
                      {audit.vendor}
                    </strong>

                    <span>
                      {audit.platform}
                    </span>

                  </div>

                  <span className="scenario-audit-status">
                    {audit.overall_status.replace(
                      "_",
                      " "
                    )}
                  </span>

                </div>


                <div className="scenario-audit-stats">

                  <div>
                    <small>Failed</small>
                    <strong className="stat-danger">
                      {audit.failed}
                    </strong>
                  </div>

                  <div>
                    <small>Manual</small>
                    <strong className="stat-warning">
                      {audit.manual}
                    </strong>
                  </div>

                  <div>
                    <small>Passed</small>
                    <strong className="stat-success">
                      {audit.passed}
                    </strong>
                  </div>

                </div>


                <div className="scenario-audit-footer">

                  <code>
                    {audit.audit_id.slice(0, 12)}…
                  </code>

                  <Link
                    href={`/attack-scenarios?audit_id=${audit.audit_id}`}
                    className="view-audit-button"
                  >
                    Analyze →
                  </Link>

                </div>

              </article>

            ))}

          </div>

        </section>

      )}

    </div>
  );
}


export default function AttackScenariosPage() {
  return (
    <Suspense
      fallback={
        <div className="scenario-loading">
          <div className="loading-spinner" />
          Loading attack scenario workspace...
        </div>
      }
    >
      <AttackScenarioWorkspace />
    </Suspense>
  );
}
