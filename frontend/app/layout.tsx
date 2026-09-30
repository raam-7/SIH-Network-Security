import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = { title: "SIH Network Security Auditor", description: "Evidence-backed network security compliance audits" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><header className="site-header"><Link href="/" className="brand"><span className="brand-mark">SI</span><span><strong>NETWORK SECURITY</strong><small>COMPLIANCE AUDITOR</small></span></Link><nav><Link href="/">Workspace</Link><Link href="/audits">Audits</Link><Link href="/attack-scenarios">Attack Scenarios</Link><Link href="/audits">Reports</Link></nav><span className="header-state">SYSTEM ONLINE</span></header><main>{children}</main></body></html>;
}
