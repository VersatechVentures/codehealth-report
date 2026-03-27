import { calculateScore, Score } from '../src/scorer';
import { Finding } from '../src/types';

// Helper to create findings quickly
const finding = (
  severity: Finding['severity'],
  type: Finding['type'],
  title = 'Test finding'
): Finding => ({ severity, type, title, description: title });

describe('Weighted Scorer', () => {
  describe('Perfect score (no findings)', () => {
    it('should return 100/A for empty findings', () => {
      const score = calculateScore([]);
      expect(score.overall).toBe(100);
      expect(score.grade).toBe('A');
      expect(score.hardGateTriggered).toBe(false);
    });

    it('should return individual profile by default', () => {
      const score = calculateScore([]);
      expect(score.profile).toBe('individual');
    });
  });

  describe('Weight distribution (40/25/20/15)', () => {
    it('security findings should have the most impact', () => {
      const secOnly = calculateScore([finding('high', 'sast')]);
      const depOnly = calculateScore([finding('high', 'sca')]);
      const qualOnly = calculateScore([finding('high', 'quality')]);
      const maintOnly = calculateScore([finding('high', 'maintainability')]);

      // Security (40%) hit should drop more than dependency (25%)
      expect(secOnly.overall).toBeLessThan(depOnly.overall);
      expect(depOnly.overall).toBeLessThan(qualOnly.overall);
      expect(qualOnly.overall).toBeLessThan(maintOnly.overall);
    });

    it('should apply correct weights mathematically', () => {
      // One medium security finding = -10 to security score
      // Overall impact = 10 * 0.4 = 4 points
      const score = calculateScore([finding('medium', 'sast')]);
      expect(score.overall).toBe(100 - 10 * 0.4); // 96
      expect(score.breakdown.security).toBe(90);
      expect(score.breakdown.dependencies).toBe(100);
      expect(score.breakdown.quality).toBe(100);
      expect(score.breakdown.maintainability).toBe(100);
    });
  });

  describe('Severity penalties', () => {
    it('critical findings should penalize more than high', () => {
      const critical = calculateScore([finding('critical', 'sast')]);
      const high = calculateScore([finding('high', 'sast')]);
      expect(critical.overall).toBeLessThan(high.overall);
    });

    it('info findings should have zero penalty', () => {
      const score = calculateScore([finding('info', 'sast')]);
      expect(score.overall).toBe(100);
    });

    it('individual profile penalties: critical=25, high=15, medium=10, low=5', () => {
      const crit = calculateScore([finding('critical', 'sast')]);
      expect(crit.breakdown.security).toBe(75); // 100 - 25

      const high = calculateScore([finding('high', 'sast')]);
      expect(high.breakdown.security).toBe(85); // 100 - 15

      const med = calculateScore([finding('medium', 'sast')]);
      expect(med.breakdown.security).toBe(90); // 100 - 10

      const low = calculateScore([finding('low', 'sast')]);
      expect(low.breakdown.security).toBe(95); // 100 - 5
    });
  });

  describe('Hard gate (enterprise)', () => {
    it('should trigger hard gate on critical security finding', () => {
      const score = calculateScore([finding('critical', 'sast')]);
      expect(score.hardGateTriggered).toBe(true);
    });

    it('should trigger hard gate on critical dependency finding', () => {
      const score = calculateScore([finding('critical', 'sca')]);
      expect(score.hardGateTriggered).toBe(true);
    });

    it('should NOT trigger hard gate on critical quality finding', () => {
      const score = calculateScore([finding('critical', 'quality')]);
      expect(score.hardGateTriggered).toBe(false);
    });

    it('enterprise profile should cap score at 49 when hard gate triggered', () => {
      const score = calculateScore([finding('critical', 'sast')], 'enterprise');
      expect(score.hardGateTriggered).toBe(true);
      expect(score.overall).toBeLessThanOrEqual(49);
      expect(score.grade).toBe('F');
    });

    it('enterprise profile should have harsher penalties', () => {
      const individual = calculateScore([finding('critical', 'sast')], 'individual');
      const enterprise = calculateScore([finding('critical', 'sast')], 'enterprise');
      // Enterprise critical penalty = 50 vs individual = 25
      expect(enterprise.breakdown.security).toBeLessThan(individual.breakdown.security);
    });
  });

  describe('Grade boundaries', () => {
    it('A: 90+', () => {
      const score = calculateScore([finding('low', 'quality')]); // tiny penalty
      expect(score.grade).toBe('A');
    });

    it('F: below 60', () => {
      // Stack enough findings to drop below 60
      // Need heavy penalties across all categories
      const findings: Finding[] = [
        finding('critical', 'sast'),
        finding('critical', 'sast'),
        finding('critical', 'sca'),
        finding('critical', 'sca'),
        finding('high', 'quality'),
        finding('high', 'quality'),
        finding('high', 'quality'),
        finding('high', 'maintainability'),
        finding('high', 'maintainability'),
        finding('high', 'maintainability'),
      ];
      const score = calculateScore(findings);
      expect(score.overall).toBeLessThan(60);
      expect(score.grade).toBe('F');
    });
  });

  describe('Score floor', () => {
    it('should never go below 0 in any category', () => {
      // Flood with critical findings
      const findings: Finding[] = Array(20).fill(null).map(() => finding('critical', 'sast'));
      const score = calculateScore(findings);
      expect(score.breakdown.security).toBeGreaterThanOrEqual(0);
      expect(score.overall).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Finding type routing', () => {
    it('sast → security', () => {
      const score = calculateScore([finding('medium', 'sast')]);
      expect(score.breakdown.security).toBe(90);
      expect(score.breakdown.dependencies).toBe(100);
    });

    it('secret → security', () => {
      const score = calculateScore([finding('medium', 'secret')]);
      expect(score.breakdown.security).toBe(90);
    });

    it('sca → dependencies', () => {
      const score = calculateScore([finding('medium', 'sca')]);
      expect(score.breakdown.dependencies).toBe(90);
      expect(score.breakdown.security).toBe(100);
    });

    it('quality → quality', () => {
      const score = calculateScore([finding('medium', 'quality')]);
      expect(score.breakdown.quality).toBe(90);
    });

    it('maintainability → maintainability', () => {
      const score = calculateScore([finding('medium', 'maintainability')]);
      expect(score.breakdown.maintainability).toBe(90);
    });
  });
});

  // === NEXUS-REQUESTED EDGE CASES ===

  describe('Malformed inputs (NEXUS critique)', () => {
    it('should handle unrecognized severity gracefully', () => {
      const badFinding = { severity: 'medium-high' as any, type: 'sast' as any, title: 'Bad', description: 'Bad' };
      const score = calculateScore([badFinding]);
      // Should not crash — unrecognized severity should be ignored
      expect(score.overall).toBeDefined();
      expect(score.overall).toBeGreaterThanOrEqual(0);
    });

    it('should handle unrecognized finding type gracefully', () => {
      const badFinding = { severity: 'high' as any, type: 'performance' as any, title: 'Perf', description: 'Perf' };
      const score = calculateScore([badFinding]);
      // Should not crash — unrecognized type won't route to any category
      expect(score.overall).toBe(100); // No penalty applied since type doesn't match
    });
  });
