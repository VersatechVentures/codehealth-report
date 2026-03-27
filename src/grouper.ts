
import { Finding, GroupedFindings } from './types';

// Based on CWE Top 25 2023 and OWASP Top 10 2021
export const CWE_CATEGORIES: { [key: string]: string } = {
  'CWE-79': 'Injection', // Cross-site Scripting
  'CWE-89': 'Injection', // SQL Injection
  'CWE-78': 'Injection', // OS Command Injection
  'CWE-22': 'Path Traversal',
  'CWE-352': 'Cross-Site Request Forgery (CSRF)',
  'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
  'CWE-276': 'Incorrect Default Permissions',
  'CWE-20': 'Improper Input Validation',
  'CWE-416': 'Use After Free',
  'CWE-125': 'Out-of-bounds Read',
  'CWE-190': 'Integer Overflow or Wraparound',
  'CWE-787': 'Out-of-bounds Write',
  'CWE-476': 'NULL Pointer Dereference',
  'CWE-287': 'Improper Authentication',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
  'CWE-94': 'Improper Control of Generation of Code (\'Code Injection\')',
  'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
  'CWE-400': 'Uncontrolled Resource Consumption',
  'CWE-611': 'Improper Restriction of XML External Entity Reference',
  'CWE-77': 'Improper Neutralization of Special Elements used in a Command (\'Command Injection\')',
};

export function groupFindings(findings: Finding[]): GroupedFindings[] {
  const grouped: { [category: string]: { cweIds: Set<string>; findings: Finding[] } } = {};
  const ungrouped: Finding[] = [];

  for (const finding of findings) {
    // Normalize CWE ID to uppercase for case-insensitive matching
    const normalizedCwe = finding.cweId?.toUpperCase();
    if (normalizedCwe && CWE_CATEGORIES[normalizedCwe]) {
      const category = CWE_CATEGORIES[normalizedCwe];
      if (!grouped[category]) {
        grouped[category] = { cweIds: new Set(), findings: [] };
      }
      grouped[category].cweIds.add(normalizedCwe);
      grouped[category].findings.push(finding);
    } else {
      ungrouped.push(finding);
    }
  }

  const result: GroupedFindings[] = Object.entries(grouped).map(([category, data]) => {
    const severities = data.findings.map(f => f.severity);
    const highestSeverity = severities.includes('critical') ? 'critical'
      : severities.includes('high') ? 'high'
      : severities.includes('medium') ? 'medium'
      : 'low';

    return {
      category,
      cweIds: Array.from(data.cweIds),
      findings: data.findings,
      severity: highestSeverity,
    };
  });

  if (ungrouped.length > 0) {
    result.push({
      category: 'Ungrouped',
      cweIds: [],
      findings: ungrouped,
      severity: 'medium', // Default severity for ungrouped, can be adjusted
    });
  }

  return result;
}
