/** CodeHealth Report — Shared Types */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingType = "sast" | "sca" | "quality" | "maintainability" | "secret";

export interface Finding {
  severity: Severity;
  type: FindingType;
  category?: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  cweId?: string;
}

export interface GroupedFindings {
  category: string;
  cweIds: string[];
  findings: Finding[];
  severity: Severity;
}

export interface Score {
  overall: number;
  breakdown: {
    security: number;
    dependencies: number;
    quality: number;
    maintainability: number;
  };
  grade: string;
  hardGateTriggered: boolean;
  profile: 'individual' | 'enterprise';
}

export interface FindingGroup {
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  count: number;
  topFinding: Finding;
}

export interface ExecutiveSummary {
  /** Risk-first headline: leads with severity counts, never quality labels */
  headline: string;
  /** Scope disclaimer: what was scanned, what was NOT scanned */
  scopeDisclaimer: string;
  /** Severity breakdown counts */
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  /** Risk statement: severity-driven, no false confidence */
  riskStatement: string;
  /** Top findings by severity (max 5), plain descriptions */
  topFindings: string[];
  /** Complexity indicator — Low | Medium | High (NOT time/dollar estimates) */
  remediationComplexity: 'Low' | 'Medium' | 'High';
  /** Actionable next steps, severity-driven */
  recommendation: string;
  /** Whether hard gate was triggered (critical finding present) */
  hardGateTriggered: boolean;
}

export interface CodeHealthReport {
  meta: {
    repoUrl: string;
    repoName: string;
    scanDate: string;
    scanDurationMs: number;
    version: string;
  };
  summary: {
    overallScore: number;
    grade: string;
    riskLevel: "low" | "medium" | "high" | "critical";
    topIssues: string[];
  };
  executive: ExecutiveSummary;
  groupedFindings: FindingGroup[];
  sections: {
    project: { raw: string };
    security: { raw: string };
    dependencies: { raw: string };
    quality: { raw: string };
    coverage: { raw: string };
    compliance: { raw: string };
  };
}

export interface ScanRequest {
  repoUrl: string;
  branch?: string;
}

export interface ScanJob {
  id: string;
  status: "queued" | "cloning" | "scanning" | "generating" | "complete" | "failed";
  repoUrl: string;
  createdAt: string;
  completedAt?: string;
  report?: CodeHealthReport;
  error?: string;
}
