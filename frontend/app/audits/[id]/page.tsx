"use client";
import Link from "next/link";
import { use, useEffect, useState } from "react";
import { getAudit, userFacingApiError } from "../../../lib/api";
import type { AuditReport } from "../../../lib/types";
import ReportView from "../../../components/audit/ReportView";

export default function AuditDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params); const [report, setReport] = useState<AuditReport | null>(null); const [error, setError] = useState("");
  useEffect(() => { void getAudit(id).then(setReport).catch(err => setError(userFacingApiError(err))); }, [id]);
  return <><div className="hero"><Link href="/audits" className="eyebrow">← Back to audit history</Link>{error ? <div className="notice error">{error}</div> : !report ? <p>Loading report…</p> : <><h1>Audit report</h1><p>{report.vendor} · {report.platform} · <StatusLine status={report.summary.overall_status} /></p><div className="panel"><div className="meta">Audit ID</div><div className="fingerprint">{id}</div><div className="meta" style={{ marginTop: 18 }}>Configuration Fingerprint</div><div className="fingerprint">{report.configuration_hash || "Not available for this historical audit"}</div><p className="meta">SHA-256 fingerprint stored for configuration provenance. Raw configuration text is not persisted by the audit repository.</p><Link className="button primary" href={`/attack-scenarios?audit_id=${id}`}>View Attack Scenarios →</Link></div></>}</div>{report && <ReportView report={report} auditId={id} />}</>;
}
function StatusLine({ status }: { status: string }) { return <strong style={{ color: status === "COMPLIANT" ? "var(--accent)" : status === "NON_COMPLIANT" ? "var(--danger)" : "var(--warn)" }}>{status}</strong>; }
