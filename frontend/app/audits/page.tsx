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

  const [vendorFilter, setVendorFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [platformFilter, setPlatformFilter] = useState("ALL");
  const [offset, setOffset] = useState(0);

  const limit = 15;

  const loadData = useCallback(
    async (currentOffset: number) => {
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
    },
    [vendorFilter, platformFilter, statusFilter]
  );

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

  const totalAudits = data?.pagination.total ?? 0;

  const compliantCount =
    data?.items.filter(
      (item) => item.overall_status === "COMPLIANT"
    ).length ?? 0;

  const nonCompliantCount =
    data?.items.filter(
      (item) => item.overall_status === "NON_COMPLIANT"
    ).length ?? 0;

  const reviewCount =
    data?.items.filter(
      (item) => item.manual > 0
    ).length ?? 0;

  const filtersActive =
    vendorFilter !== "ALL" ||
    statusFilter !== "ALL" ||
    platformFilter !== "ALL";

  return (
    <div className="audits-page">

      {/* =====================================================
          PAGE HEADER
          ===================================================== */}

      <section className="page-header">
        <span className="eyebrow">SECURITY AUDIT REPOSITORY</span>

        <div className="audit-history-title-row">
          <div>
            <h1>Audit History</h1>

            <p>
              Review previous network security assessments, compliance
              results, findings, and audit evidence in one place.
            </p>
          </div>

          <Link href="/" className="button primary">
            + New Audit
          </Link>
        </div>
      </section>


      {/* =====================================================
          SUMMARY CARDS
          ===================================================== */}

      <section className="history-summary-grid">

        <div className="history-summary-card">
          <div className="summary-card-top">
            <span>Total Audits</span>
            <span className="summary-icon blue">▤</span>
          </div>

          <strong>{totalAudits}</strong>

          <small>Audits in repository</small>
        </div>

        <div className="history-summary-card">
          <div className="summary-card-top">
            <span>Compliant</span>
            <span className="summary-icon green">✓</span>
          </div>

          <strong>{compliantCount}</strong>

          <small>On current page</small>
        </div>

        <div className="history-summary-card">
          <div className="summary-card-top">
            <span>Needs Attention</span>
            <span className="summary-icon red">!</span>
          </div>

          <strong>{nonCompliantCount}</strong>

          <small>Non-compliant audits</small>
        </div>

        <div className="history-summary-card">
          <div className="summary-card-top">
            <span>Review Required</span>
            <span className="summary-icon orange">◷</span>
          </div>

          <strong>{reviewCount}</strong>

          <small>Audits with manual review</small>
        </div>

      </section>


      {/* =====================================================
          FILTERS
          ===================================================== */}

      <section className="history-filter-card">

        <div className="filter-heading">
          <div>
            <strong>Find an audit</strong>
            <span>
              Filter the repository by vendor, compliance state or platform.
            </span>
          </div>

          {filtersActive && (
            <span className="filter-active-badge">
              Filters active
            </span>
          )}
        </div>

        <div className="history-filter-grid">

          <div className="filter-group">
            <label htmlFor="filter-vendor">
              Vendor
            </label>

            <select
              id="filter-vendor"
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
            >
              <option value="ALL">All Vendors</option>
              <option value="cisco">Cisco</option>
              <option value="juniper">Juniper</option>
              <option value="fortigate">FortiGate</option>
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="filter-status">
              Compliance Status
            </label>

            <select
              id="filter-status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="COMPLIANT">Compliant</option>
              <option value="NON_COMPLIANT">
                Non-Compliant
              </option>
              <option value="REVIEW_REQUIRED">
                Review Required
              </option>
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="filter-platform">
              Platform
            </label>

            <select
              id="filter-platform"
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
            >
              <option value="ALL">All Platforms</option>
              <option value="ios-xe">IOS-XE</option>
              <option value="ios">IOS</option>
            </select>
          </div>

          <button
            type="button"
            className="history-reset-button"
            onClick={handleResetFilters}
            disabled={!filtersActive}
          >
            Reset filters
          </button>

        </div>
      </section>


      {/* =====================================================
          ERROR
          ===================================================== */}

      {error && (
        <div className="history-error" role="alert">
          <div>
            <strong>Unable to load audit history</strong>
            <p>{error}</p>
          </div>

          <button
            type="button"
            className="button"
            onClick={() => void loadData(offset)}
          >
            Retry
          </button>
        </div>
      )}


      {/* =====================================================
          AUDIT TABLE
          ===================================================== */}

      <section className="history-table-card">

        <div className="history-table-header">
          <div>
            <span className="eyebrow">AUDIT REPOSITORY</span>
            <h2>Recent assessments</h2>
          </div>

          {data && (
            <span className="repository-count">
              {data.pagination.total} total audits
            </span>
          )}
        </div>


        {loading ? (
          <div className="history-loading">
            <div className="loading-spinner" />
            <strong>Loading audit repository...</strong>
            <span>Fetching persisted security assessments.</span>
          </div>

        ) : !data || data.items.length === 0 ? (

          <div className="empty-state history-empty">
            <div className="empty-icon">▤</div>

            <h3>No audits found</h3>

            <p>
              {filtersActive
                ? "No persisted audits match the selected filters."
                : "Run your first configuration security audit to create an assessment."}
            </p>

            <Link href="/" className="button primary">
              Start New Audit →
            </Link>
          </div>

        ) : (

          <>

            <div className="audit-table">

              <div className="audit-table-head">
                <span>Status</span>
                <span>Vendor</span>
                <span>Platform</span>
                <span>Findings</span>
                <span>Review</span>
                <span>Created</span>
                <span>Audit</span>
                <span />
              </div>


              {data.items.map((item) => (

                <div
                  className="audit-table-row"
                  key={item.audit_id}
                >

                  <div>
                    <StatusBadge value={item.overall_status} />
                  </div>


                  <div className="vendor-cell">
                    <strong>
                      {item.vendor}
                    </strong>

                    <span>
                      Network device
                    </span>
                  </div>


                  <div>
                    <span className="platform-pill">
                      {item.platform}
                    </span>
                  </div>


                  <div className="finding-counts">

                    <span className="finding-count failed">
                      {item.failed}
                      <small>failed</small>
                    </span>

                    <span className="finding-count manual">
                      {item.manual}
                      <small>manual</small>
                    </span>

                    <span className="finding-count passed">
                      {item.passed}
                      <small>passed</small>
                    </span>

                  </div>


                  <div>
                    {item.manual > 0 ? (
                      <span className="review-pill pending">
                        {item.manual} pending
                      </span>
                    ) : (
                      <span className="review-pill complete">
                        Complete
                      </span>
                    )}
                  </div>


                  <div className="created-cell">
                    {formatAuditDate(item.created_at)}
                  </div>


                  <div className="audit-id-cell">
                    <code>
                      {item.audit_id.slice(0, 8)}…
                    </code>
                  </div>


                  <div className="audit-action">
                    <Link
                      href={`/audits/${item.audit_id}`}
                      className="view-audit-button"
                    >
                      View →
                    </Link>
                  </div>

                </div>

              ))}

            </div>


            {/* =================================================
                PAGINATION
                ================================================= */}

            <div className="history-pagination">

              <span>
                Showing{" "}
                <strong>
                  {data.pagination.offset + 1}
                </strong>
                {" – "}
                <strong>
                  {Math.min(
                    data.pagination.offset +
                      data.items.length,
                    data.pagination.total
                  )}
                </strong>
                {" of "}
                <strong>
                  {data.pagination.total}
                </strong>
              </span>

              <div>

                <button
                  type="button"
                  className="pagination-button"
                  disabled={
                    data.pagination.offset === 0 ||
                    loading
                  }
                  onClick={() =>
                    handlePageChange(
                      Math.max(
                        0,
                        data.pagination.offset - limit
                      )
                    )
                  }
                >
                  ← Previous
                </button>

                <button
                  type="button"
                  className="pagination-button"
                  disabled={
                    !data.pagination.has_more ||
                    loading
                  }
                  onClick={() =>
                    handlePageChange(
                      data.pagination.offset + limit
                    )
                  }
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

  if (Number.isNaN(parsed.getTime())) {
    return "Unknown date";
  }

  return parsed.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}