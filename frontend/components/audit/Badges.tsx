import type { FindingResult, FindingSeverity, OverallStatus } from "../../lib/types";
export function StatusBadge({ value }: { value: OverallStatus | FindingResult }) { return <span className={`badge ${value}`}>{value}</span>; }
export function SeverityBadge({ value }: { value: FindingSeverity }) { return <span className="badge">{value}</span>; }
