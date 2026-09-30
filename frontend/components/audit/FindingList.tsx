"use client";
import { useState } from "react";
import { createHumanReview, userFacingApiError } from "../../lib/api";
import type { AuditReportFinding, HumanReview, HumanReviewDecision } from "../../lib/types";
import { SeverityBadge, StatusBadge } from "./Badges";

export default function FindingList({ findings, auditId }: { findings: AuditReportFinding[]; auditId?: string }) {
  const [reviews, setReviews] = useState<Record<string, HumanReview>>({});
  const [query, setQuery] = useState(""); const [result, setResult] = useState("ALL"); const [severity, setSeverity] = useState("ALL");
  const visible = findings.filter(finding => finding.rule_id.toLowerCase().includes(query.toLowerCase()) || finding.title.toLowerCase().includes(query.toLowerCase())).filter(finding => result === "ALL" || finding.result === result).filter(finding => severity === "ALL" || finding.severity === severity);
  return <div><div className="finding-toolbar"><input className="select" aria-label="Search findings" placeholder="Search findings..." value={query} onChange={event => setQuery(event.target.value)} /><select className="select" aria-label="Filter result" value={result} onChange={event => setResult(event.target.value)}><option value="ALL">All results</option><option value="PASS">PASS</option><option value="FAIL">FAIL</option><option value="MANUAL">MANUAL</option></select><select className="select" aria-label="Filter severity" value={severity} onChange={event => setSeverity(event.target.value)}><option value="ALL">All severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></div>{visible.length === 0 ? <div className="empty">No compliance findings match the selected filters.</div> : visible.map((finding, index) => { const id = `${finding.rule_id}-${index}`; return <FindingCard key={id} finding={finding} auditId={auditId} review={reviews[id] || finding.review || undefined} onReview={review => setReviews(current => ({ ...current, [id]: review }))} />; })}</div>;
}

function FindingCard({ finding, auditId, review, onReview }: { finding: AuditReportFinding; auditId?: string; review?: HumanReview; onReview: (review: HumanReview) => void }) {
  const [comment, setComment] = useState("");
  const [savedComment, setSavedComment] = useState("");
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState<HumanReviewDecision | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const displayedComment = review?.reviewer_reason || savedComment;
  const submit = async () => {
    if (!confirming) return;
    setBusy(true); setError("");
    try { const result = await createHumanReview(finding, confirming, displayedComment.trim() || "Reviewed configuration evidence.", auditId); onReview({ ...result, status: "REVIEWED" }); setConfirming(null); setEditing(false); }
    catch (err) { setError(userFacingApiError(err)); } finally { setBusy(false); }
  };
  return <article className="finding">
    <div className="finding-head"><div><h3>{finding.title}</h3><span className="meta">{finding.rule_id}</span></div><div className="actions" style={{ marginTop: 0 }}><StatusBadge value={finding.result} /><SeverityBadge value={finding.severity} /><span className="badge">RISK {finding.risk_level}</span></div></div>
    <p>{finding.description}</p>
    <div className="finding-grid"><div className="evidence"><span className="label">Evidence score · {finding.evidence_score}/100</span><span className="meta">{finding.evidence_type}{finding.evidence.exact_text && ` · line ${finding.evidence.line_start}`}</span><code className="code">{finding.evidence.exact_text || "No supporting configuration evidence found."}</code></div><div className="remediation"><span className="label">Semantic interpretation</span>{finding.semantic_concept ? <p>{finding.semantic_concept} · {finding.semantic_property} = {String(finding.semantic_value)}<br />Mapping: {finding.mapping_source}{finding.ai_confidence != null && ` · AI confidence ${Math.round(finding.ai_confidence * 100)}%`}</p> : <p>No semantic mapping available.</p>}{finding.remediation && <><span className="label">Remediation · {finding.remediation_mode}</span><code className="code">{finding.remediation}</code></>}</div></div>
    {finding.result === "MANUAL" && <section className={`review-panel ${review ? "reviewed" : "pending"}`} aria-label="Human review"><div className="review-heading"><span className="label">Human review</span><span className={`review-status ${review ? "reviewed" : "pending"}`}>{review ? "REVIEWED" : "PENDING"}</span></div>{review ? <><div className="review-field"><span className="label">Review decision</span><strong>{review.decision}</strong></div><div className="review-field"><span className="label">Reviewer comment</span><p>{review.reviewer_reason}</p></div></> : <><div className="review-field"><span className="label">Reviewer comment</span>{editing ? <><textarea aria-label="Reviewer comment" value={comment} onChange={event => setComment(event.target.value)} placeholder="Explain the manual verification" /><div className="actions review-actions"><button className="button" disabled={busy || comment.trim() === savedComment.trim()} onClick={() => { setSavedComment(comment.trim()); setEditing(false); }}>Save</button><button className="button" disabled={busy} onClick={() => { setComment(savedComment); setEditing(false); }}>Cancel</button></div></> : <><p>{savedComment || "No reviewer comment added."}</p><button className="button review-edit" onClick={() => { setComment(savedComment); setEditing(true); }}>Edit</button></>}</div><div className="review-field"><span className="label">Review decision</span><div className="actions review-actions"><button className="button" disabled={busy} onClick={() => setConfirming("COMPLIANT")}>Mark Compliant</button><button className="button" disabled={busy} onClick={() => setConfirming("NON_COMPLIANT")}>Mark Non-Compliant</button></div></div></>}{confirming && <div className="review-confirm"><p>Confirm marking this finding as <strong>{confirming}</strong>?</p><div className="actions"><button className="button primary" disabled={busy} onClick={() => void submit()}>{busy ? "Submitting review…" : "Confirm"}</button><button className="button" disabled={busy} onClick={() => setConfirming(null)}>Cancel</button></div></div>}{error && <div className="notice error">{error}</div>}</section>}
  </article>;
}
