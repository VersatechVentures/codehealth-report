/**
 * Knowledge Base — Auto-Capture System
 *
 * Captures structured knowledge from scan events, decisions, and research.
 * Stores as JSON files in /knowledge/ directory for future querying.
 *
 * Phase 4 deliverable. Three triggers:
 * 1. Scan completion → captures report summary + findings
 * 2. Decision recording → captures adversarial debate outcomes
 * 3. Research completion → captures competitive intel + market data
 */

import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CodeHealthReport } from './types';

const KNOWLEDGE_DIR = path.join(__dirname, '..', 'knowledge');

export interface KnowledgeEntry {
  id: string;
  version: 1;
  type: 'scan_result' | 'decision' | 'research' | 'incident';
  timestamp: string;
  agent: 'openclaw' | 'nexus' | 'system';
  trigger: string;
  title: string;
  summary: string;
  tags: string[];
  data: Record<string, any>;
}

/**
 * Ensure knowledge directory exists
 */
function ensureDir(): void {
  if (!fs.existsSync(KNOWLEDGE_DIR)) {
    fs.mkdirSync(KNOWLEDGE_DIR, { recursive: true });
  }
}

/**
 * Store a knowledge entry
 */
export function storeKnowledge(entry: KnowledgeEntry): string {
  ensureDir();
  const filename = `${entry.type}_${entry.id}.json`;
  const filepath = path.join(KNOWLEDGE_DIR, filename);
  fs.writeFileSync(filepath, JSON.stringify(entry, null, 2), 'utf-8');
  console.log(`[Knowledge] Stored: ${filename} (${entry.type}: ${entry.title})`);
  return filepath;
}

/**
 * Retrieve all knowledge entries, optionally filtered by type or tags
 */
export function queryKnowledge(filters?: {
  type?: KnowledgeEntry['type'];
  tags?: string[];
  since?: string;
}): KnowledgeEntry[] {
  ensureDir();
  const files = fs.readdirSync(KNOWLEDGE_DIR).filter(f => f.endsWith('.json'));
  let entries: KnowledgeEntry[] = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(path.join(KNOWLEDGE_DIR, file), 'utf-8');
      entries.push(JSON.parse(content));
    } catch { /* skip corrupt files */ }
  }

  if (filters?.type) {
    entries = entries.filter(e => e.type === filters.type);
  }
  if (filters?.tags && filters.tags.length > 0) {
    entries = entries.filter(e =>
      filters.tags!.some(tag => e.tags.includes(tag))
    );
  }
  if (filters?.since) {
    entries = entries.filter(e => e.timestamp >= filters.since!);
  }

  // Sort by timestamp, newest first
  return entries.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

/**
 * Auto-capture hook: Scan Completion
 * Called after every successful scan to record findings in the knowledge base.
 */
export function captureScanResult(report: CodeHealthReport): string {
  const entry: KnowledgeEntry = {
    id: uuidv4(),
    version: 1,
    type: 'scan_result',
    agent: 'system',
    trigger: 'scan_completion',
    timestamp: new Date().toISOString(),
    title: `Scan: ${report.meta.repoName}`,
    summary: report.executive.headline,
    tags: [
      report.meta.repoName,
      `grade:${report.summary.grade}`,
      `risk:${report.summary.riskLevel}`,
      ...(report.executive.hardGateTriggered ? ['hard-gate'] : []),
    ],
    data: {
      repoUrl: report.meta.repoUrl,
      repoName: report.meta.repoName,
      score: report.summary.overallScore,
      grade: report.summary.grade,
      riskLevel: report.summary.riskLevel,
      severityCounts: report.executive.severityCounts,
      topFindings: report.executive.topFindings,
      remediationComplexity: report.executive.remediationComplexity,
      hardGateTriggered: report.executive.hardGateTriggered,
      scanDurationMs: report.meta.scanDurationMs,
      version: report.meta.version,
      groupedFindingCategories: report.groupedFindings.map(g => g.category),
    },
  };

  return storeKnowledge(entry);
}

/**
 * Auto-capture hook: Decision Recording
 * Called when a product/technical decision is made through adversarial debate.
 */
export function captureDecision(decision: {
  title: string;
  outcome: string;
  rationale: string;
  counterArgument: string;
  whatWeLost: string;
  revisitTrigger: string;
  debateRound: number;
  participants: string[];
}): string {
  const entry: KnowledgeEntry = {
    id: uuidv4(),
    version: 1,
    type: 'decision',
    agent: 'openclaw',
    trigger: 'adversarial_debate',
    timestamp: new Date().toISOString(),
    title: decision.title,
    summary: `${decision.outcome} (after ${decision.debateRound} rounds)`,
    tags: ['decision', ...decision.participants],
    data: decision,
  };

  return storeKnowledge(entry);
}

/**
 * Auto-capture hook: Research Completion
 * Called when competitive research or market analysis is completed.
 */
export function captureResearch(research: {
  topic: string;
  summary: string;
  sources: string[];
  keyFindings: string[];
  implications: string[];
  actionItems: string[];
}): string {
  const entry: KnowledgeEntry = {
    id: uuidv4(),
    version: 1,
    type: 'research',
    agent: 'openclaw',
    trigger: 'research_completion',
    timestamp: new Date().toISOString(),
    title: `Research: ${research.topic}`,
    summary: research.summary,
    tags: ['research', research.topic.toLowerCase().replace(/\s+/g, '-')],
    data: research,
  };

  return storeKnowledge(entry);
}

/**
 * Auto-capture hook: Incident Recording
 * Called when a bug, outage, or system failure occurs.
 */
export function captureIncident(incident: {
  title: string;
  description: string;
  rootCause: string;
  fix: string;
  preventionMeasure: string;
  filesAffected: string[];
}): string {
  const entry: KnowledgeEntry = {
    id: uuidv4(),
    version: 1,
    type: 'incident',
    agent: 'system',
    trigger: 'error_handler',
    timestamp: new Date().toISOString(),
    title: `Incident: ${incident.title}`,
    summary: `${incident.rootCause} → ${incident.fix}`,
    tags: ['incident', ...incident.filesAffected.map(f => `file:${f}`)],
    data: incident,
  };

  return storeKnowledge(entry);
}
