import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CodeHealthReport } from './types';
import { Request, Response, NextFunction } from 'express';

const KNOWLEDGE_DIR = path.join(__dirname, '..', 'knowledge');

// Base Interface
export interface KnowledgeEntry<T> {
  id: string;
  version: 1;
  type: 'scan_result' | 'decision' | 'incident';
  timestamp: string;
  agent: 'openclaw' | 'nexus' | 'system';
  trigger: string;
  data: T;
}

// Specific Data Payloads
export interface ScanResultData {
  repoUrl: string;
  report: CodeHealthReport;
}

export interface IncidentData {
  error: {
    message: string;
    stack?: string;
  };
  request: {
    endpoint: string;
    method: string;
    body: any;
    headers: any;
  };
  rootCause?: string;
  preventionStrategy?: string;
}

export interface DecisionData {
  title: string;
  chosenOption: string;
  rejectedAlternatives: {
    option: string;
    reason: string;
  }[];
  tradeOffs: string;
  agentsInvolved: ('openclaw' | 'nexus')[];
}

function ensureDir(): void {
  if (!fs.existsSync(KNOWLEDGE_DIR)) {
    fs.mkdirSync(KNOWLEDGE_DIR, { recursive: true });
  }
}

function storeKnowledge<T>(entry: KnowledgeEntry<T>): string {
  ensureDir();
  const filename = `${entry.type}_${entry.id}.json`;
  const filepath = path.join(KNOWLEDGE_DIR, filename);
  fs.writeFileSync(filepath, JSON.stringify(entry, null, 2), 'utf-8');
  console.log(`[Knowledge] Stored: ${filename}`);
  return filepath;
}

export function captureScanResult(repoUrl: string, report: CodeHealthReport): string {
  const entry: KnowledgeEntry<ScanResultData> = {
    id: uuidv4(),
    version: 1,
    type: 'scan_result',
    timestamp: new Date().toISOString(),
    agent: 'system',
    trigger: 'scan_completion',
    data: {
      repoUrl,
      report,
    },
  };
  return storeKnowledge(entry);
}

export function captureIncident(
  err: Error,
  req: Request,
  rootCause?: string,
  preventionStrategy?: string
): string {
  const entry: KnowledgeEntry<IncidentData> = {
    id: uuidv4(),
    version: 1,
    type: 'incident',
    timestamp: new Date().toISOString(),
    agent: 'system',
    trigger: 'error_handler',
    data: {
      error: {
        message: err.message,
        stack: err.stack,
      },
      request: {
        endpoint: req.originalUrl,
        method: req.method,
        body: req.body,
        headers: req.headers,
      },
      rootCause,
      preventionStrategy,
    },
  };
  return storeKnowledge(entry);
}

export function captureDecision(
  title: string,
  chosenOption: string,
  rejectedAlternatives: { option: string; reason: string }[],
  tradeOffs: string,
  agentsInvolved: ('openclaw' | 'nexus')[]
): string {
  const entry: KnowledgeEntry<DecisionData> = {
    id: uuidv4(),
    version: 1,
    type: 'decision',
    timestamp: new Date().toISOString(),
    agent: 'nexus', // Or determined dynamically
    trigger: 'manual_capture',
    data: {
      title,
      chosenOption,
      rejectedAlternatives,
      tradeOffs,
      agentsInvolved,
    },
  };
  return storeKnowledge(entry);
}

// Global Error Handler Middleware
export function knowledgeBaseErrorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  captureIncident(err, req);
  // Fallback to default Express error handler
  next(err);
}
