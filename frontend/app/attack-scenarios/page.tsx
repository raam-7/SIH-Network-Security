"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { getAudit, getAudits, userFacingApiError } from "../../lib/api";
import type { AuditHistoryResponse, AuditReport } from "../../lib/types";
import AttackScenarios from "../../components/audit/AttackScenarios";

function AttackScenarioWorkspace() {
  const params = useSearchParams();
  const selectedId = params.get("audit_id") || "";
  const [audits, setAudits] = useState<AuditHistoryResponse | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => { void getAudits(15, 0).then(setAudits).catch(err => setError(userFacingApiError(err))).finally(() => setLoading(false)); }, []);
  useEffect(() => { if (selectedId) void getAudit(selectedId).then(setReport).catch(err => setError(userFacingApiError(err))); else void Promise.resolve().then(() => setReport(null)); }, [selectedId]);
  if (loading) return <section className="hero"><span className="eyebrow">Defensive analysis</span><h1>Attack Scenario Analysis</h1><p>Loading persisted audits…</p></section>;
  if (error) return <section className="hero"><h1>Attack Scenario Analysis</h1><div className="notice error">{error}</div><Link className="button" href="/audits">Open audit history</Link></section>;
  if (report) return <section><div className="hero compact-hero"><Link href="/attack-scenarios" className="eyebrow">← Select another audit</Link><h1>Attack Scenarios</h1><p>{report.vendor} · {report.platform} · <strong>{report.summary.overall_status.replace("_", " ")}</strong></p><span className="meta">{report.summary.failed} failed · {report.summary.manual} manual · Audit {selectedId.slice(0, 12)}…</span><p><Link className="button" href={`/audits/${selectedId}`}>Back to Audit</Link></p></div><AttackScenarios scenarios={report.attack_scenarios ?? []} /></section>;
  return <section className="hero"><span className="eyebrow">Defensive analysis</span><h1>Attack Scenario Analysis</h1><p>Select a persisted audit to inspect defensive attack paths derived from its actual compliance findings.</p><div className="notice">Defensive attack-path modeling based on configuration findings. No exploitation is performed.</div>{!audits || audits.items.length === 0 ? <><p>No persisted audits are available yet.</p><Link className="button primary" href="/">Run an Audit →</Link></> : <div className="audit-picker"><h2>Recent audits</h2>{audits.items.map(audit => <article className="audit-picker-row" key={audit.audit_id}><div><strong>{audit.vendor} · {audit.platform}</strong><span className="meta">{audit.audit_id.slice(0, 12)}… · {new Date(audit.created_at).toISOString().slice(0, 10)}</span></div><span className="meta">{audit.failed} failed · {audit.manual} manual</span><Link className="button" href={`/attack-scenarios?audit_id=${audit.audit_id}`}>View Attack Scenarios</Link></article>)}</div>}</section>;
}
export default function AttackScenariosPage() { return <Suspense fallback={<p>Loading attack scenario workspace…</p>}><AttackScenarioWorkspace /></Suspense>; }
