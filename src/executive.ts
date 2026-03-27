/**
 * Risk-First Executive Summary Generator
 *
 * Design principles (from adversarial review):
 * - Lead with severity counts, not quality labels
 * - Scope disclaimers on every report
 * - Never say "your code is secure"
 * - No dollar or time estimates — only Low/Medium/High complexity
 * - Severity-driven language only
 */

import { Finding, ExecutiveSummary, Severity } from './types';
import { Score } from './scorer';
import { GroupedFindings } from './types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface ExecutiveSummaryInput {
  findings: Finding[];
  score: Score;
  groupedFindings: GroupedFindings[];
  repoName: string;
  /** Which scan tools actually ran */
  scannedAreas: string[];
}

/**
 * Generate the risk-first executive summary.
 * Never claims safety — only reports what was found and what was scanned.
 */
export function generateExecutiveSummary(input: ExecutiveSummaryInput): ExecutiveSummary {
  const { findings, score, groupedFindings, repoName, scannedAreas } = input;

  // 1. Severity counts
  const severityCounts = countSeverities(findings);

  // 2. Headline — leads with severity, never "healthy" or "clean"
  const headline = buildHeadline(severityCounts, score);

  // 3. Scope disclaimer — what we scanned, what we didn't
  const scopeDisclaimer = buildScopeDisclaimer(repoName, scannedAreas);

  // 4. Risk statement — factual, severity-driven
  const riskStatement = buildRiskStatement(severityCounts, score, groupedFindings);

  // 5. Top findings — up to 5, highest severity first
  const topFindings = extractTopFindings(findings, groupedFindings);

  // 6. Remediation complexity — Low/Medium/High, no time/dollar estimates
  const remediationComplexity = assessComplexity(severityCounts, groupedFindings);

  // 7. Recommendation — actionable, severity-driven
  const recommendation = buildRecommendation(severityCounts, score);

  return {
    headline,
    scopeDisclaimer,
    severityCounts,
    riskStatement,
    topFindings,
    remediationComplexity,
    hardGateTriggered: score.hardGateTriggered,
    recommendation,
  };
}

function countSeverities(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity as keyof Omit<typeof counts, 'total'>]++;
    }
    counts.total++;
  }
  return counts;
}

function buildHeadline(
  counts: ReturnType<typeof countSeverities>,
  score: Score
): string {
  if (counts.total === 0) {
    return `No findings detected in scanned areas — ${score.overall}/100`;
  }

  // Build severity fragments: "3 critical, 7 high, 12 medium"
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const n = counts[sev as keyof Omit<typeof counts, 'total'>];
    if (n > 0 && sev !== 'info') {
      parts.push(`${n} ${sev}`);
    }
  }

  const findingsStr = parts.join(', ');

  if (score.hardGateTriggered) {
    return `⛔ ${counts.total} findings detected (${findingsStr}) — Needs Immediate Attention`;
  }

  if (counts.critical > 0 || counts.high > 0) {
    return `${counts.total} findings detected (${findingsStr}) — Score: ${score.overall}/100`;
  }

  return `${counts.total} findings detected (${findingsStr}) — Score: ${score.overall}/100`;
}

function buildScopeDisclaimer(repoName: string, scannedAreas: string[]): string {
  const scanned = scannedAreas.length > 0
    ? scannedAreas.join(', ')
    : 'static analysis, dependency audit, code quality, maintainability';

  const notScanned = [
    'runtime behavior',
    'deployment configuration',
    'infrastructure security',
    'business logic flaws',
    'authentication flow correctness',
  ];

  return (
    `This report covers ${repoName} across the following scanned areas: ${scanned}. ` +
    `This scan does NOT cover: ${notScanned.join(', ')}. ` +
    `Findings reflect automated analysis only and should be validated by a qualified engineer before action.`
  );
}

function buildRiskStatement(
  counts: ReturnType<typeof countSeverities>,
  score: Score,
  groupedFindings: GroupedFindings[]
): string {
  if (counts.total === 0) {
    return (
      'No findings were detected in the scanned areas. ' +
      'This does not guarantee the absence of vulnerabilities — ' +
      'only that automated scanning did not identify issues within its scope.'
    );
  }

  const lines: string[] = [];

  // Hard gate warning
  if (score.hardGateTriggered) {
    lines.push(
      `Critical findings detected. ` +
      `${score.profile === 'enterprise' ? 'Enterprise compliance gate triggered — this repository does not meet minimum security requirements.' : 'Immediate remediation is strongly recommended.'}`
    );
  }

  // Severity breakdown sentence
  const severityParts: string[] = [];
  if (counts.critical > 0) severityParts.push(`${counts.critical} critical`);
  if (counts.high > 0) severityParts.push(`${counts.high} high-severity`);
  if (counts.medium > 0) severityParts.push(`${counts.medium} medium-severity`);
  if (counts.low > 0) severityParts.push(`${counts.low} low-severity`);

  lines.push(`${counts.total} total findings identified: ${severityParts.join(', ')}.`);

  // Category breakdown
  const categorized = groupedFindings
    .filter(g => g.category !== 'Ungrouped')
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });

  if (categorized.length > 0) {
    const topCategories = categorized.slice(0, 3).map(
      g => `${g.category} (${g.findings.length} findings, highest: ${g.severity})`
    );
    lines.push(`Primary concern areas: ${topCategories.join('; ')}.`);
  }

  // Score context
  lines.push(
    `Weighted score: ${score.overall}/100 (Security ${score.breakdown.security}/100, ` +
    `Dependencies ${score.breakdown.dependencies}/100, ` +
    `Quality ${score.breakdown.quality}/100, ` +
    `Maintainability ${score.breakdown.maintainability}/100).`
  );

  return lines.join(' ');
}

function extractTopFindings(
  findings: Finding[],
  groupedFindings: GroupedFindings[]
): string[] {
  // Sort by severity, take top 5
  const sorted = [...findings].sort((a, b) => {
    const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });

  return sorted.slice(0, 5).map(f => {
    const location = f.file ? ` in ${f.file}${f.line ? `:${f.line}` : ''}` : '';
    const cwe = f.cweId ? ` (${f.cweId})` : '';
    return `[${f.severity.toUpperCase()}] ${f.title}${cwe}${location}`;
  });
}

function assessComplexity(
  counts: ReturnType<typeof countSeverities>,
  groupedFindings: GroupedFindings[]
): 'Low' | 'Medium' | 'High' {
  // High: any critical findings, or 5+ high findings, or 3+ distinct categories with high+ severity
  if (counts.critical > 0) return 'High';

  const highSevCategories = groupedFindings.filter(
    g => g.severity === 'critical' || g.severity === 'high'
  ).length;

  if (counts.high >= 5 || highSevCategories >= 3) return 'High';

  // Medium: any high findings, or 10+ medium findings
  if (counts.high > 0 || counts.medium >= 10) return 'Medium';

  // Low: everything else
  return 'Low';
}

function buildRecommendation(
  counts: ReturnType<typeof countSeverities>,
  score: Score
): string {
  if (counts.total === 0) {
    return (
      'No automated findings to remediate. Consider manual security review ' +
      'and penetration testing for areas outside automated scan scope.'
    );
  }

  const lines: string[] = [];

  if (counts.critical > 0) {
    lines.push(
      `Address ${counts.critical} critical finding${counts.critical > 1 ? 's' : ''} immediately — ` +
      `these represent the highest risk to the codebase.`
    );
  }

  if (counts.high > 0) {
    lines.push(
      `Remediate ${counts.high} high-severity finding${counts.high > 1 ? 's' : ''} as a priority.`
    );
  }

  if (counts.medium > 0) {
    lines.push(
      `Review ${counts.medium} medium-severity finding${counts.medium > 1 ? 's' : ''} and address in the next development cycle.`
    );
  }

  if (counts.low > 0) {
    lines.push(
      `${counts.low} low-severity finding${counts.low > 1 ? 's' : ''} can be addressed as part of routine maintenance.`
    );
  }

  if (score.hardGateTriggered && score.profile === 'enterprise') {
    lines.push(
      'Enterprise compliance gate was triggered. This repository should not be deployed ' +
      'to production until critical findings are resolved.'
    );
  }

  return lines.join(' ');
}
