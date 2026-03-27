import fs from 'fs';
import path from 'path';
import {
  storeKnowledge,
  queryKnowledge,
  captureScanResult,
  captureDecision,
  captureResearch,
  captureIncident,
  KnowledgeEntry,
} from '../src/knowledge';
import { scanRepo } from '../src/scanner';

const KNOWLEDGE_DIR = path.join(__dirname, '..', 'knowledge');

// Clean up before each test
beforeEach(() => {
  if (fs.existsSync(KNOWLEDGE_DIR)) {
    const files = fs.readdirSync(KNOWLEDGE_DIR).filter(f => f.endsWith('.json'));
    for (const file of files) {
      fs.unlinkSync(path.join(KNOWLEDGE_DIR, file));
    }
  }
});

describe('Knowledge Base', () => {
  describe('storeKnowledge', () => {
    it('should write a JSON file to the knowledge directory', () => {
      const entry: KnowledgeEntry = {
        id: 'test_1',
        version: 1,
        type: 'decision',
        timestamp: new Date().toISOString(),
        agent: 'openclaw',
        trigger: 'test',
        title: 'Test Decision',
        summary: 'We decided X',
        tags: ['test'],
        data: { outcome: 'X' },
      };

      const filepath = storeKnowledge(entry);
      expect(fs.existsSync(filepath)).toBe(true);

      const stored = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
      expect(stored.title).toBe('Test Decision');
      expect(stored.type).toBe('decision');
    });
  });

  describe('queryKnowledge', () => {
    it('should return all entries when no filters', () => {
      storeKnowledge({ id: 'a', version: 1, type: 'decision', timestamp: '2026-01-01', title: 'A', summary: '', tags: [], agent: 'system' as const, trigger: 'manual' as const, data: {} });
      storeKnowledge({ id: 'b', version: 1, type: 'research', timestamp: '2026-01-02', title: 'B', summary: '', tags: [], agent: 'system' as const, trigger: 'manual' as const, data: {} });

      const results = queryKnowledge();
      expect(results.length).toBe(2);
    });

    it('should filter by type', () => {
      storeKnowledge({ id: 'a', version: 1, type: 'decision', timestamp: '2026-01-01', title: 'A', summary: '', tags: [], agent: 'system' as const, trigger: 'manual' as const, data: {} });
      storeKnowledge({ id: 'b', version: 1, type: 'research', timestamp: '2026-01-02', title: 'B', summary: '', tags: [], agent: 'system' as const, trigger: 'manual' as const, data: {} });

      const results = queryKnowledge({ type: 'decision' });
      expect(results.length).toBe(1);
      expect(results[0].title).toBe('A');
    });

    it('should filter by tags', () => {
      storeKnowledge({ id: 'a', version: 1, type: 'decision', timestamp: '2026-01-01', title: 'A', summary: '', tags: ['scoring'], agent: 'system' as const, trigger: 'manual' as const, data: {} });
      storeKnowledge({ id: 'b', version: 1, type: 'decision', timestamp: '2026-01-02', title: 'B', summary: '', tags: ['grouping'], agent: 'system' as const, trigger: 'manual' as const, data: {} });

      const results = queryKnowledge({ tags: ['scoring'] });
      expect(results.length).toBe(1);
      expect(results[0].title).toBe('A');
    });

    it('should sort by timestamp (newest first)', () => {
      storeKnowledge({ id: 'old', version: 1, type: 'decision', timestamp: '2026-01-01', title: 'Old', summary: '', tags: [], agent: 'system' as const, trigger: 'manual' as const, data: {} });
      storeKnowledge({ id: 'new', version: 1, type: 'decision', timestamp: '2026-03-26', title: 'New', summary: '', tags: [], agent: 'system' as const, trigger: 'manual' as const, data: {} });

      const results = queryKnowledge();
      expect(results[0].title).toBe('New');
    });
  });

  describe('captureScanResult', () => {
    it('should auto-capture a scan report to the knowledge base', async () => {
      const report = await scanRepo('/tmp/fake', 'https://github.com/test/knowledge-test');
      const filepath = captureScanResult(report);

      expect(fs.existsSync(filepath)).toBe(true);

      const entry: KnowledgeEntry = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
      expect(entry.type).toBe('scan_result');
      expect(entry.title).toContain('test/knowledge-test');
      expect(entry.tags).toContain('test/knowledge-test');
      expect(entry.tags).toContain('grade:B');
      expect(entry.data.score).toBe(81);
    });
  });

  describe('captureDecision', () => {
    it('should record an adversarial debate outcome', () => {
      const filepath = captureDecision({
        title: 'Scoring Weights',
        outcome: '4-category (40/25/20/15)',
        rationale: 'False precision worse than honest simplicity',
        counterArgument: '5-category better for enterprise',
        whatWeLost: 'Granularity for compliance-focused buyers',
        revisitTrigger: 'When scanner produces structured coverage scores',
        debateRound: 3,
        participants: ['OpenClaw', 'NEXUS'],
      });

      const entry: KnowledgeEntry = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
      expect(entry.type).toBe('decision');
      expect(entry.data.debateRound).toBe(3);
      expect(entry.tags).toContain('OpenClaw');
      expect(entry.tags).toContain('NEXUS');
    });
  });

  describe('captureIncident', () => {
    it('should record a system incident', () => {
      const filepath = captureIncident({
        title: 'NEXUS stream termination',
        description: 'Copilot API dropped connections',
        rootCause: 'Context window too large (58KB collab channel)',
        fix: 'Archived old messages, reduced context to 30 lines',
        preventionMeasure: 'Auto-archive when collab channel exceeds 200 lines',
        filesAffected: ['memory.ts', 'orchestrator.ts'],
      });

      const entry: KnowledgeEntry = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
      expect(entry.type).toBe('incident');
      expect(entry.tags).toContain('file:memory.ts');
    });
  });
});
