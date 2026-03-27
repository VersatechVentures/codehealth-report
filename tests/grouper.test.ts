import { groupFindings, CWE_CATEGORIES } from '../src/grouper';
import { Finding } from '../src/types';

const finding = (
  severity: Finding['severity'],
  type: Finding['type'],
  cweId?: string,
  title = 'Test finding'
): Finding => ({ severity, type, title, description: title, cweId });

describe('CWE-Based Finding Grouper', () => {
  describe('CWE category mapping', () => {
    it('should map CWE-89 to Injection', () => {
      expect(CWE_CATEGORIES['CWE-89']).toBe('Injection');
    });

    it('should map CWE-79 to Injection (XSS)', () => {
      expect(CWE_CATEGORIES['CWE-79']).toBe('Injection');
    });

    it('should cover CWE Top 25', () => {
      // At minimum we should have 20+ mappings
      expect(Object.keys(CWE_CATEGORIES).length).toBeGreaterThanOrEqual(20);
    });
  });

  describe('Grouping logic', () => {
    it('should group findings by CWE category', () => {
      const findings: Finding[] = [
        finding('high', 'sast', 'CWE-89', 'SQL Injection in login'),
        finding('medium', 'sast', 'CWE-79', 'XSS in search'),
      ];
      const groups = groupFindings(findings);
      // Both CWE-89 and CWE-79 map to 'Injection'
      const injectionGroup = groups.find(g => g.category === 'Injection');
      expect(injectionGroup).toBeDefined();
      expect(injectionGroup!.findings.length).toBe(2);
      expect(injectionGroup!.cweIds).toContain('CWE-89');
      expect(injectionGroup!.cweIds).toContain('CWE-79');
    });

    it('should put findings without CWE into Ungrouped bucket', () => {
      const findings: Finding[] = [
        finding('low', 'quality', undefined, 'Code smell'),
      ];
      const groups = groupFindings(findings);
      const ungrouped = groups.find(g => g.category === 'Ungrouped');
      expect(ungrouped).toBeDefined();
      expect(ungrouped!.findings.length).toBe(1);
    });

    it('should return empty array for no findings', () => {
      const groups = groupFindings([]);
      expect(groups).toEqual([]);
    });

    it('should roll up severity to highest in group', () => {
      const findings: Finding[] = [
        finding('medium', 'sast', 'CWE-89', 'Medium SQL issue'),
        finding('critical', 'sast', 'CWE-79', 'Critical XSS'),
      ];
      const groups = groupFindings(findings);
      const injectionGroup = groups.find(g => g.category === 'Injection');
      expect(injectionGroup!.severity).toBe('critical');
    });
  });

  describe('Multiple categories', () => {
    it('should create separate groups for different categories', () => {
      const findings: Finding[] = [
        finding('high', 'sast', 'CWE-89', 'SQL Injection'),
        finding('high', 'sast', 'CWE-287', 'Auth bypass'),
        finding('medium', 'sast', 'CWE-22', 'Path traversal'),
      ];
      const groups = groupFindings(findings);
      const categories = groups.map(g => g.category);
      expect(categories).toContain('Injection');
      expect(categories).toContain('Improper Authentication');
      expect(categories).toContain('Path Traversal');
    });
  });
});

  // === NEXUS-REQUESTED EDGE CASES ===

  describe('Unmapped CWEs (NEXUS critique)', () => {
    it('should put findings with valid but unmapped CWE into Ungrouped', () => {
      const findings: Finding[] = [
        finding('medium', 'sast', 'CWE-1021', 'Unmapped CWE finding'),
      ];
      const groups = groupFindings(findings);
      const ungrouped = groups.find(g => g.category === 'Ungrouped');
      expect(ungrouped).toBeDefined();
      expect(ungrouped!.findings[0].cweId).toBe('CWE-1021');
    });

    it('should handle mixed mapped and unmapped CWEs', () => {
      const findings: Finding[] = [
        finding('high', 'sast', 'CWE-89', 'SQL Injection'),
        finding('medium', 'sast', 'CWE-9999', 'Unknown CWE'),
      ];
      const groups = groupFindings(findings);
      expect(groups.find(g => g.category === 'Injection')).toBeDefined();
      expect(groups.find(g => g.category === 'Ungrouped')).toBeDefined();
    });
  });

  describe('Case-insensitivity (NEXUS critique + bug fix)', () => {
    it('should handle lowercase CWE IDs', () => {
      const findings: Finding[] = [
        finding('high', 'sast', 'cwe-89', 'SQL Injection lowercase'),
      ];
      const groups = groupFindings(findings);
      const injectionGroup = groups.find(g => g.category === 'Injection');
      expect(injectionGroup).toBeDefined();
      expect(injectionGroup!.findings.length).toBe(1);
    });

    it('should handle mixed-case CWE IDs', () => {
      const findings: Finding[] = [
        finding('high', 'sast', 'Cwe-79', 'XSS mixed case'),
      ];
      const groups = groupFindings(findings);
      expect(groups.find(g => g.category === 'Injection')).toBeDefined();
    });
  });
