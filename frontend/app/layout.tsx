import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "NetSentinel — Network Security Compliance Auditor",
  description: "AI-driven multi-vendor network security compliance auditing",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="app-shell">

          <aside className="sidebar">
            <Link href="/" className="sidebar-brand">
              <span className="sidebar-logo">NS</span>
              <span>
                <strong>NetSentinel</strong>
                <small>SECURITY AUDITOR</small>
              </span>
            </Link>

            <div className="sidebar-section">
              <span className="sidebar-label">WORKSPACE</span>

              <Link href="/" className="sidebar-link active">
                <span>⌂</span>
                Dashboard
              </Link>

              <Link href="/" className="sidebar-link">
                <span>＋</span>
                New Audit
              </Link>

              <Link href="/audits" className="sidebar-link">
                <span>▤</span>
                Audit History
              </Link>

              <Link href="/attack-scenarios" className="sidebar-link">
                <span>⌁</span>
                Attack Scenarios
              </Link>

              <Link href="/audits" className="sidebar-link">
                <span>▣</span>
                Reports
              </Link>
            </div>

            <div className="sidebar-bottom">
              <Link href="/audits" className="sidebar-link">
                <span>⚙</span>
                Settings
              </Link>

              <div className="sidebar-status">
                <span className="status-dot" />
                <div>
                  <strong>System Online</strong>
                  <small>Audit engine ready</small>
                </div>
              </div>
            </div>
          </aside>

          <div className="app-content">
            <header className="topbar">
              <div>
                <span className="topbar-title">Network Security</span>
                <span className="topbar-subtitle">Compliance Workspace</span>
              </div>

              <div className="topbar-actions">
                <span className="topbar-secure">
                  <span className="status-dot" />
                  Secure
                </span>
              </div>
            </header>

            <main>{children}</main>
          </div>

        </div>
      </body>
    </html>
  );
}
