"use client";

import { useState } from "react";
import Link from "next/link";
import { createAudit, createVendorAudit, userFacingApiError } from "../lib/api";
import { vendorOptions } from "../lib/vendors";
import type { AuditReport } from "../lib/types";
import ReportView from "../components/audit/ReportView";

const demo =
  "aaa new-model\nip ssh version 1\nip ssh time-out 120\nline vty 0 4\n transport input telnet\n";

export default function Home() {
  const [vendor, setVendor] = useState("auto");
  const [configuration, setConfiguration] = useState("");
  const [report, setReport] = useState<AuditReport | null>(null);
  const [auditId, setAuditId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function runAudit() {
    if (!configuration.trim()) {
      setError("Paste a configuration before running the audit.");
      return;
    }

    setError("");
    setLoading(true);
    setReport(null);

    try {
      const result =
        vendor === "cisco"
          ? await createAudit(configuration)
          : await createVendorAudit(vendor, configuration);

      setReport(result.report);
      setAuditId(result.audit_id);
    } catch (err) {
      setError(userFacingApiError(err));
    } finally {
      setLoading(false);
    }
  }

  const lineCount = configuration
    ? configuration.split(/\r?\n/).length
    : 0;

  return (
    <>
      {/* HERO */}
      <section className="dashboard-hero">
        <div>
          <span className="eyebrow">AI-POWERED NETWORK SECURITY</span>

          <h1>
            Secure your network.
            <br />
            <span>Stay ahead.</span>
          </h1>

          <p>
            Automatically audit multi-vendor network configurations,
            identify security gaps, and get clear remediation guidance.
          </p>

          <div className="hero-actions">
            <button
              className="button primary hero-button"
              onClick={() =>
                document
                  .getElementById("new-audit")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Start Security Audit →
            </button>

            <button
              className="button demo-button"
              onClick={() => {
                setVendor("cisco");
                setConfiguration(demo);
                document
                  .getElementById("new-audit")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              ▶ Watch Demo
            </button>
          </div>
        </div>

        <div className="hero-visual">
          <div className="network-orbit orbit-one" />
          <div className="network-orbit orbit-two" />

          <div className="security-shield">
            <span>✓</span>
          </div>

          <div className="vendor-float vendor-cisco">Cisco</div>
          <div className="vendor-float vendor-juniper">Juniper</div>
          <div className="vendor-float vendor-fortinet">Fortinet</div>
          <div className="vendor-float vendor-palo">Palo Alto</div>
        </div>
      </section>

      {/* FEATURE CARDS */}
      <section className="feature-grid">
        <article className="feature-card">
          <div className="feature-icon blue">▦</div>
          <h3>Multi-Vendor Support</h3>
          <p>
            Audit Cisco, Juniper, Fortinet, Palo Alto and more through
            one common workflow.
          </p>
        </article>

        <article className="feature-card">
          <div className="feature-icon purple">✦</div>
          <h3>AI-Powered Analysis</h3>
          <p>
            Understand configuration findings with clear,
            evidence-backed explanations.
          </p>
        </article>

        <article className="feature-card">
          <div className="feature-icon green">✓</div>
          <h3>Actionable Remediation</h3>
          <p>
            Get structured recommendations for fixing failed
            security controls.
          </p>
        </article>

        <article className="feature-card">
          <div className="feature-icon orange">◈</div>
          <h3>Compliance Ready</h3>
          <p>
            Deterministic compliance decisions with evidence and
            risk visibility.
          </p>
        </article>
      </section>

      {/* NEW AUDIT */}
      <section id="new-audit" className="audit-workspace">
        <div className="workspace-header">
          <div>
            <span className="eyebrow">NEW SECURITY AUDIT</span>
            <h2>Create a new audit</h2>
            <p>
              Select your vendor and paste the device configuration
              to begin analysis.
            </p>
          </div>

          <span className="analysis-badge">
            ● Analysis Engine Ready
          </span>
        </div>

        <div className="audit-steps">
          <div className="audit-step active">
            <span>1</span>
            <strong>Input Configuration</strong>
          </div>

          <div className="audit-step">
            <span>2</span>
            <strong>AI Analysis</strong>
          </div>

          <div className="audit-step">
            <span>3</span>
            <strong>View Results</strong>
          </div>
        </div>

        <div className="vendor-picker">
          <label className="label">Select Vendor</label>

          <div className="vendor-options">
            {vendorOptions.map((option) => (
              <button
                type="button"
                key={option.value}
                className={`vendor-option ${
                  vendor === option.value ? "selected" : ""
                }`}
                onClick={() => setVendor(option.value)}
              >
                <span className="vendor-logo">
                  {option.value === "auto"
                    ? "◎"
                    : option.label.charAt(0)}
                </span>

                <span>{option.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="configuration-area">
          <div className="configuration-header">
            <label className="label">Configuration Input</label>

            <button
              className="sample-button"
              type="button"
              onClick={() => setConfiguration(demo)}
              disabled={loading}
            >
              Load Sample Configuration
            </button>
          </div>

          <div className="editor-wrapper">
            <div className="line-numbers">
              {Array.from(
                { length: Math.max(lineCount, 8) },
                (_, i) => (
                  <span key={i}>{i + 1}</span>
                )
              )}
            </div>

            <textarea
              id="configuration"
              className="audit-editor"
              value={configuration}
              onChange={(e) => setConfiguration(e.target.value)}
              placeholder={`Paste your network configuration here...

Example:
aaa new-model
ip ssh version 2
ip ssh time-out 60
line vty 0 4
 transport input ssh`}
            />
          </div>

          <div className="editor-footer">
            <span>
              Supported: .txt, .cfg, .conf
            </span>

            <span>
              {configuration.length} characters · {lineCount} lines
            </span>
          </div>

          {error && (
            <div className="notice error" role="alert">
              {error}
            </div>
          )}

          <button
            className="button primary audit-run-button"
            onClick={runAudit}
            disabled={loading}
          >
            {loading
              ? "Analyzing Configuration..."
              : "Run Security Audit →"}
          </button>
        </div>
      </section>

      {/* PIPELINE */}
      <section className="simple-pipeline">
        <div>
          <span className="eyebrow">HOW NETSENTINEL WORKS</span>
          <h2>From configuration to clear security insight.</h2>
        </div>

        <div className="pipeline-horizontal">
          {[
            ["01", "Configuration"],
            ["02", "Vendor Parser"],
            ["03", "AI Normalization"],
            ["04", "Compliance Engine"],
            ["05", "Risk & Evidence"],
          ].map(([number, label]) => (
            <div className="pipeline-item" key={number}>
              <span>{number}</span>
              <strong>{label}</strong>
            </div>
          ))}
        </div>
      </section>

      {/* REAL RESULT */}
      {report && (
        <>
          <div className="section-title">
            <div>
              <span className="eyebrow">AUDIT COMPLETE</span>
              <h2>Security Audit Result</h2>
            </div>

            {auditId && (
              <Link
                className="button"
                href={`/audits/${auditId}`}
              >
                Open Full Report →
              </Link>
            )}
          </div>

          <ReportView report={report} />
        </>
      )}
    </>
  );
}
