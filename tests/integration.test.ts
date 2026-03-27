/**
 * Integration tests for CodeHealth API endpoints.
 * Tests the full request → response cycle without starting the server.
 */
import { scanRepo } from '../src/scanner';
import { generatePDFReport } from '../src/reporter';
import { CodeHealthReport } from '../src/types';

describe('Scanner Integration', () => {
  let report: CodeHealthReport;

  beforeAll(async () => {
    // Run a full scan — uses mock data in demo mode
    report = await scanRepo('/tmp/fake-repo', 'https://github.com/test/repo');
  }, 30000);

  it('should return a complete report object', () => {
    expect(report).toBeDefined();
    expect(report.meta).toBeDefined();
    expect(report.summary).toBeDefined();
    expect(report.executive).toBeDefined();
    expect(report.sections).toBeDefined();
    expect(report.groupedFindings).toBeDefined();
  });

  it('should include correct meta', () => {
    expect(report.meta.repoUrl).toBe('https://github.com/test/repo');
    expect(report.meta.repoName).toBe('test/repo');
    expect(report.meta.version).toContain('demo');
    expect(report.meta.scanDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('should calculate a valid score', () => {
    expect(report.summary.overallScore).toBeGreaterThanOrEqual(0);
    expect(report.summary.overallScore).toBeLessThanOrEqual(100);
    expect(['A', 'B', 'C', 'D', 'F']).toContain(report.summary.grade);
    expect(['low', 'medium', 'high', 'critical']).toContain(report.summary.riskLevel);
  });

  it('should generate executive summary with all required fields', () => {
    const exec = report.executive;
    expect(exec.headline).toBeTruthy();
    expect(exec.scopeDisclaimer).toContain('does NOT cover');
    expect(exec.severityCounts).toBeDefined();
    expect(exec.severityCounts.total).toBeGreaterThanOrEqual(0);
    expect(exec.riskStatement).toBeTruthy();
    expect(exec.topFindings).toBeInstanceOf(Array);
    expect(['Low', 'Medium', 'High']).toContain(exec.remediationComplexity);
    expect(typeof exec.hardGateTriggered).toBe('boolean');
    expect(exec.recommendation).toBeTruthy();
  });

  it('should populate all 6 scan sections', () => {
    expect(report.sections.project.raw).toBeTruthy();
    expect(report.sections.security.raw).toBeTruthy();
    expect(report.sections.dependencies.raw).toBeTruthy();
    expect(report.sections.quality.raw).toBeTruthy();
    expect(report.sections.coverage.raw).toBeTruthy();
    expect(report.sections.compliance.raw).toBeTruthy();
  });

  it('should include demo watermark in section output', () => {
    expect(report.sections.security.raw).toContain('DEMO MODE');
    expect(report.sections.dependencies.raw).toContain('DEMO MODE');
  });

  it('should group findings with CWE categories', () => {
    expect(report.groupedFindings.length).toBeGreaterThan(0);
    for (const group of report.groupedFindings) {
      expect(group.category).toBeTruthy();
      expect(group.severity).toBeTruthy();
      expect(group.count).toBeGreaterThan(0);
    }
  });
});

describe('PDF Reporter Integration', () => {
  it('should generate a valid PDF buffer from a report', async () => {
    // First generate a report
    const report = await scanRepo('/tmp/fake-repo', 'https://github.com/test/pdf-gen');

    // Then generate PDF
    const pdfBuffer = await generatePDFReport(report);

    expect(pdfBuffer).toBeDefined();
    expect(pdfBuffer.length).toBeGreaterThan(0);
    // PDF magic bytes: %PDF
    expect(pdfBuffer[0]).toBe(0x25); // %
    expect(pdfBuffer[1]).toBe(0x50); // P
    expect(pdfBuffer[2]).toBe(0x44); // D
    expect(pdfBuffer[3]).toBe(0x46); // F
  }, 60000); // PDF generation can take a while with Puppeteer
});
