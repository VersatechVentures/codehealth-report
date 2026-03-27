import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

const DB_DIR = path.join(process.cwd(), 'data');
const DB_PATH = path.join(DB_DIR, 'codehealth.db');

let db: Database.Database;

export function initDB(): Database.Database {
  if (db) return db;
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      tier TEXT DEFAULT 'free',
      scans_this_month INTEGER DEFAULT 0,
      scans_reset_date TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS scan_jobs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      repo_url TEXT NOT NULL,
      status TEXT NOT NULL,
      report JSON,
      created_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      error TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS shared_reports (
      share_id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      report JSON NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT,
      FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
    );
  `);

  return db;
}

export function getDB(): Database.Database {
  if (!db) initDB();
  return db;
}

// ─── Scan Jobs ───

export function saveJob(job: { id: string; user_id?: string; repo_url: string; status: string; report?: any; completed_at?: string; error?: string }): void {
  const d = getDB();
  const existing = d.prepare('SELECT id FROM scan_jobs WHERE id = ?').get(job.id);
  if (existing) {
    d.prepare(`UPDATE scan_jobs SET status = ?, report = ?, completed_at = ?, error = ? WHERE id = ?`)
      .run(job.status, job.report ? JSON.stringify(job.report) : null, job.completed_at || null, job.error || null, job.id);
  } else {
    d.prepare(`INSERT INTO scan_jobs (id, user_id, repo_url, status, report, completed_at, error) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(job.id, job.user_id || null, job.repo_url, job.status, job.report ? JSON.stringify(job.report) : null, job.completed_at || null, job.error || null);
  }
}

export function getJob(id: string): any | null {
  const row = getDB().prepare('SELECT * FROM scan_jobs WHERE id = ?').get(id) as any;
  if (!row) return null;
  if (row.report) row.report = JSON.parse(row.report);
  return row;
}

// ─── Shared Reports ───

export function saveSharedReport(shareId: string, jobId: string, report: any): void {
  getDB().prepare(`INSERT INTO shared_reports (share_id, job_id, report) VALUES (?, ?, ?)`)
    .run(shareId, jobId, JSON.stringify(report));
}

export function getSharedReport(shareId: string): any | null {
  const row = getDB().prepare('SELECT * FROM shared_reports WHERE share_id = ?').get(shareId) as any;
  if (!row) return null;
  if (row.report) row.report = JSON.parse(row.report);
  return row;
}

// ─── Users ───

export function createUser(email: string, passwordHash: string, tier = 'free'): { id: string; email: string; tier: string } {
  const id = uuidv4();
  const now = new Date();
  const resetDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  getDB().prepare(`INSERT INTO users (id, email, password_hash, tier, scans_this_month, scans_reset_date) VALUES (?, ?, ?, ?, 0, ?)`)
    .run(id, email, passwordHash, tier, resetDate);
  return { id, email, tier };
}

export function getUserByEmail(email: string): any | null {
  return getDB().prepare('SELECT * FROM users WHERE email = ?').get(email) || null;
}

export function getUserById(id: string): any | null {
  return getDB().prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
}

export function incrementScanCount(userId: string): number {
  const d = getDB();
  const now = new Date();
  const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const user = d.prepare('SELECT scans_this_month, scans_reset_date FROM users WHERE id = ?').get(userId) as any;
  if (!user) return 0;

  if (user.scans_reset_date !== currentMonth) {
    d.prepare('UPDATE users SET scans_this_month = 1, scans_reset_date = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .run(currentMonth, userId);
    return 1;
  }

  d.prepare('UPDATE users SET scans_this_month = scans_this_month + 1, updated_at = datetime(\'now\') WHERE id = ?')
    .run(userId);
  return user.scans_this_month + 1;
}

export function resetScanCount(userId: string): void {
  const now = new Date();
  const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  getDB().prepare('UPDATE users SET scans_this_month = 0, scans_reset_date = ?, updated_at = datetime(\'now\') WHERE id = ?')
    .run(currentMonth, userId);
}
