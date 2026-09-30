import type { AuditHistoryResponse, AuditReport, AuditReportFinding, HumanReview, HumanReviewDecision } from "./types";

const baseUrl = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000/api/v1").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(public readonly status: number, detail: string, statusText: string) {
    super(`API request failed: ${status} ${statusText}${detail ? `: ${detail}` : ""}`);
    this.name = "ApiError";
  }
}

export function userFacingApiError(error: unknown): string {
  if (!(error instanceof ApiError)) return "Unable to connect to the backend API. Check that the API is running.";
  if (error.status === 400) return "Invalid audit request.";
  if (error.status === 404) return "Audit not found.";
  if (error.status === 422) return "Invalid request data.";
  if (error.status >= 500) return "Backend audit service returned an internal error.";
  return error.message;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;
  try { response = await fetch(`${baseUrl}${path}`, options); }
  catch { throw new Error("Unable to connect to the backend API. Check that the API is running."); }
  if (!response.ok) {
    let detail = "";
    try { const body = await response.json(); detail = body.detail || body.message || ""; } catch { /* non-JSON error */ }
    throw new ApiError(response.status, detail, response.statusText || "Request Failed");
  }
  return response.json() as Promise<T>;
}

export function createAudit(configuration: string) {
  return request<{ audit_id: string; report: AuditReport }>("/audits", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ configuration }),
  });
}
export function getAudit(id: string) { return request<AuditReport>(`/audits/${encodeURIComponent(id)}`); }
export function getAudits(limit = 20, offset = 0, vendor?: string, platform?: string, overallStatus?: string) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (vendor && vendor !== "ALL") params.set("vendor", vendor);
  if (platform && platform !== "ALL") params.set("platform", platform);
  if (overallStatus && overallStatus !== "ALL") params.set("overall_status", overallStatus);
  return request<AuditHistoryResponse>(`/audits?${params.toString()}`);
}
export function createHumanReview(finding: AuditReportFinding, decision: HumanReviewDecision, reviewerReason: string, auditId?: string) {
  return request<HumanReview>("/reviews", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ audit_id: auditId, finding, decision, reviewer: "audit-reviewer", reviewer_reason: reviewerReason }) });
}
