import { generateExecutiveSummary } from '../src/executive';
import { Finding } from '../src/types';
import { Score } from '../src/scorer';

const finding = (
  severity: Finding['severity'],
  type: Finding['type'],
  title: string,
  cweId?: string
): Finding => ({ severity, type, title, description: title, cweId });

const baseScore = (overrides: Partial<Score> = {}): Score => ({
  overall: 81,
  breakdown: { security: 78, dependencies: 82, quality: 88, maintainability: 90 },
  grade: 'B',
  hardGateTriggered: false,
  profile: 'individual',
  ...overrides,
});

describe('Risk-First Executive Summary', () => {
  describe('Headline', () => {
    it('should lead with severity counts, not quality labels', () => {
      const summary = generateExecutiveSummary({
        findings: [
          finding('high', 'sast', 'XSS in search'),
          finding('medium', 'sca', 'Outdated dep'),
          finding('medium', 'quality', 'Code smell'),
        ],
        score: baseScore(),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: ['static analysis'],
      });

      expect(summary.headline).toContain('3 findings detected');
      expect(summary.headline).toContain('1 high');
      expect(summary.headline).toContain('2 medium');
      expect(summary.headline).toContain('81/100');
      // Should NOT contain quality labels like "good" or "healthy"
      expect(summary.headline.toLowerCase()).not.toContain('good');
      expect(summary.headline.toLowerCase()).not.toContain('healthy');
      expect(summary.headline.toLowerCase()).not.toContain('clean');
    });

    it('should show hard gate warning for critical findings', () => {
      const summary = generateExecutiveSummary({
        findings: [finding('critical', 'sast', 'SQLi')],
        score: baseScore({ hardGateTriggered: true, overall: 45 }),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });

      expect(summary.headline).toContain('Needs Immediate Attention');
      expect(summary.hardGateTriggered).toBe(true);
    });

    it('should never say "secure" for zero findings', () => {
      const summary = generateExecutiveSummary({
        findings: [],
        score: baseScore({ overall: 100 }),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });

      expect(summary.headline.toLowerCase()).not.toContain('secure');
      expect(summary.headline).toContain('No findings detected');
      expect(summary.headline).toContain('scanned areas');
    });
  });

  describe('Scope disclaimer', () => {
    it('should list what was and was NOT scanned', () => {
      const summary = generateExecutiveSummary({
        findings: [],
        score: baseScore(),
        groupedFindings: [],
        repoName: 'expressjs/express',
        scannedAreas: ['static analysis', 'dependency audit'],
      });

      expect(summary.scopeDisclaimer).toContain('expressjs/express');
      expect(summary.scopeDisclaimer).toContain('static analysis');
      expect(summary.scopeDisclaimer).toContain('does NOT cover');
      expect(summary.scopeDisclaimer).toContain('runtime behavior');
      expect(summary.scopeDisclaimer).toContain('validated by a qualified engineer');
    });
  });

  describe('Remediation complexity', () => {
    it('should be High when critical findings exist', () => {
      const summary = generateExecutiveSummary({
        findings: [finding('critical', 'sast', 'Critical vuln')],
        score: baseScore({ hardGateTriggered: true }),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });
      expect(summary.remediationComplexity).toBe('High');
    });

    it('should be Low when only low/info findings', () => {
      const summary = generateExecutiveSummary({
        findings: [
          finding('low', 'quality', 'Minor issue'),
          finding('info', 'quality', 'Info note'),
        ],
        score: baseScore({ overall: 95 }),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });
      expect(summary.remediationComplexity).toBe('Low');
    });
  });

  describe('No effort estimates (adversarial debate requirement)', () => {
    it('should not contain dollar amounts', () => {
      const summary = generateExecutiveSummary({
        findings: [finding('high', 'sast', 'XSS')],
        score: baseScore(),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });

      const allText = JSON.stringify(summary);
      expect(allText).not.toMatch(/\$\d/);
      expect(allText.toLowerCase()).not.toContain('hours');
      expect(allText.toLowerCase()).not.toContain('days');
      expect(allText.toLowerCase()).not.toContain('weeks');
    });
  });
});

  // === NEXUS-REQUESTED EDGE CASES ===

  describe('Empty states (NEXUS critique)', () => {
    it('should handle zero findings with empty groupedFindings', () => {
      const summary = generateExecutiveSummary({
        findings: [],
        score: baseScore({ overall: 100, grade: 'A' }),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: ['static analysis'],
      });
      expect(summary.headline).toContain('No findings detected');
      expect(summary.severityCounts.total).toBe(0);
      expect(summary.remediationComplexity).toBe('Low');
    });
  });

  describe('Top findings prioritization (NEXUS critique)', () => {
    it('should sort top findings by severity (critical first)', () => {
      const summary = generateExecutiveSummary({
        findings: [
          finding('low', 'quality', 'Minor thing'),
          finding('critical', 'sast', 'SQL Injection'),
          finding('medium', 'sca', 'Outdated dep'),
          finding('high', 'sast', 'XSS'),
        ],
        score: baseScore({ hardGateTriggered: true }),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });
      // First finding should be critical
      expect(summary.topFindings[0]).toContain('CRITICAL');
      // Second should be high
      expect(summary.topFindings[1]).toContain('HIGH');
    });

    it('should limit top findings to 5', () => {
      const findings = Array(20).fill(null).map((_, i) =>
        finding('medium', 'sast', `Finding ${i}`)
      );
      const summary = generateExecutiveSummary({
        findings,
        score: baseScore(),
        groupedFindings: [],
        repoName: 'test/repo',
        scannedAreas: [],
      });
      expect(summary.topFindings.length).toBeLessThanOrEqual(5);
    });
  });
