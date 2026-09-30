"use client";

import Link from "next/link";
import { useEffect, useState, useCallback } from "react";
import { getAudits, userFacingApiError } from "../../lib/api";
import type { AuditHistoryResponse } from "../../lib/types";
import { StatusBadge } from "../../components/audit/Badges";

export default function AuditsPage() {
  const [data, setData] = useState<AuditHistoryResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  // Filters connected to backend DB
  const [vendorFilter, setVendorFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [platformFilter, setPlatformFilter] = useState("ALL");
  const [offset, setOffset] = useState(0);
  const limit = 15;

  const loadData = useCallback(async (currentOffset: number) => {
    setLoading(true);
    setError("");
    try {
      const result = await getAudits(
        limit,
        currentOffset,
        vendorFilter,
        platformFilter,
        statusFilter
      );
      setData(result);
    } catch (err) {
      setError(userFacingApiError(err));
    } finally {
      setLoading(false);
    }
  }, [vendorFilter, platformFilter, statusFilter, limit]);

  useEffect(() => {
    void Promise.resolve().then(() => loadData(0));
  }, [vendorFilter, platformFilter, statusFilter, loadData]);

  const handlePageChange = (newOffset: number) => {
    setOffset(newOffset);
    void loadData(newOffset);
  };

  const handleResetFilters = () => {
    setVendorFilter("ALL");
    setStatusFilter("ALL");
    setPlatformFilter("ALL");
    setOffset(0);
  };

  return (
    <div className="audits-page">
      {/* Page Header */}
      <div className="workspace-hero">
        <span className="hero-tag">SECURITY AUDIT REPOSITORY</span>
        <h1 className="hero-title">AUDIT HISTORY</h1>
        <p className="hero-subtitle">
          Search and inspect historical security compliance assessments,
          cryptographic provenance hashes, and line-level evidence traces.
        </p>
      </div>

      {/* Filter Control Bar */}
      <div className="history-filter-card">
        <div className="filter-group">
          <label htmlFor="filter-vendor" className="filter-label">Vendor</label>
          <select
            id="filter-vendor"
            className="filter-control"
            value={vendorFilter}
            onChange={e => setVendorFilter(e.target.value)}
          >
            <option value="ALL">All Vendors</option>
            <option value="cisco">Cisco</option>
            <option value="juniper">Juniper</option>
            <option value="fortigate">FortiGate</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="filter-status" className="filter-label">Compliance Status</label>
          <select
            id="filter-status"
            className="filter-control"
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPLIANT">Compliant</option>
            <option value="NON_COMPLIANT">Non-Compliant</option>
            <option value="REVIEW_REQUIRED">Review Required</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="filter-platform" className="filter-label">Platform</label>
          <select
            id="filter-platform"
            className="filter-control"
            value={platformFilter}
            onChange={e => setPlatformFilter(e.target.value)}
          >
            <option value="ALL">All Platforms</option>
            <option value="ios-xe">IOS-XE</option>
            <option value="ios">IOS</option>
          </select>
        </div>

        <div className="filter-actions">
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={handleResetFilters}
            disabled={vendorFilter === "ALL" && statusFilter === "ALL" && platformFilter === "ALL"}
          >
            Reset Filters
          </button>
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div className="alert-card alert-error mt-4" role="alert">
          <div className="alert-header">
            <strong>AUDIT REPOSITORY NOTICE</strong>
          </div>
          <p>{error}</p>
          <button
            type="button"
            className="btn btn-xs btn-outline mt-2"
            onClick={() => void loadData(offset)}
          >
            Retry Loading
          </button>
        </div>
      )}

      {/* Main Table Panel */}
      <section className="panel mt-4">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            <p>Loading audit assessments from repository…</p>
          </div>
        ) : !data || data.items.length === 0 ? (
          <div className="empty-state">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
            <h3>NO AUDITS YET</h3>
            <p>
              {vendorFilter !== "ALL" || statusFilter !== "ALL" || platformFilter !== "ALL"
                ? "No persisted audits matched the selected filter criteria."
                : "Run your first configuration security audit to begin."}
            </p>
            <Link href="/" className="btn btn-primary mt-4">
              Go to Audit Workspace →
            </Link>
          </div>
        ) : (
          <>
            <div className="table-responsive">
              <table className="enterprise-table">
                <thead>
                  <tr>
                    <th>STATUS</th>
                    <th>VENDOR</th>
                    <th>PLATFORM</th>
                    <th>FINDINGS</th>
                    <th>REVIEW STATE</th>
                    <th>CREATED AT</th>
                    <th>AUDIT ID</th>
                    <th className="text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map(item => (
                    <tr key={item.audit_id} className="table-row-hover">
                      <td>
                        <StatusBadge value={item.overall_status} />
                      </td>
                      <td>
                        <span className="font-semibold text-main">{item.vendor}</span>
                      </td>
                      <td>
                        <span className="platform-tag">{item.platform}</span>
                      </td>
                      <td>
                        <span className="findings-summary-text">
                          <span className="text-fail">{item.failed} failed</span> /{" "}
                          <span className="text-warn">{item.manual} manual</span> /{" "}
                          <span className="text-pass">{item.passed} passed</span>
                        </span>
                      </td>
                      <td>
                        <span className={`review-state-text ${item.manual > 0 ? "text-warn" : "text-muted"}`}>
                          {item.manual > 0 ? `${item.manual} pending` : "0 pending"}
                        </span>
                      </td>
                      <td className="text-muted font-mono text-xs">
                        {formatAuditDate(item.created_at)}
                      </td>
                      <td>
                        <span className="hash-code-sm font-mono">
                          {item.audit_id.slice(0, 10)}…
                        </span>
                      </td>
                      <td className="text-right">
                        <Link
                          href={`/audits/${item.audit_id}`}
                          className="btn btn-xs btn-outline"
                        >
                          View Audit →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="pagination-bar">
              <span className="pagination-info">
                Showing {data.pagination.offset + 1}–
                {Math.min(data.pagination.offset + data.items.length, data.pagination.total)} of{" "}
                <strong>{data.pagination.total}</strong> matching audits
              </span>

              <div className="pagination-buttons">
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  disabled={data.pagination.offset === 0 || loading}
                  onClick={() => handlePageChange(Math.max(0, data.pagination.offset - limit))}
                >
                  ← Previous
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  disabled={!data.pagination.has_more || loading}
                  onClick={() => handlePageChange(data.pagination.offset + limit)}
                >
                  Next →
                </button>
              </div>
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function formatAuditDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown date" : `${parsed.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
