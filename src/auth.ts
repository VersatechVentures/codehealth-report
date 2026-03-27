import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import * as fs from 'fs';
import * as path from 'path';
import { Request, Response, NextFunction } from 'express';
import { createUser, getUserByEmail, getUserById } from './database';

const DATA_DIR = path.join(process.cwd(), 'data');
const SECRET_PATH = path.join(DATA_DIR, 'jwt.secret');

function getJwtSecret(): string {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(SECRET_PATH)) return fs.readFileSync(SECRET_PATH, 'utf-8').trim();
  const secret = require('crypto').randomBytes(64).toString('hex');
  fs.writeFileSync(SECRET_PATH, secret, { mode: 0o600 });
  return secret;
}

const JWT_SECRET = getJwtSecret();

export interface AuthUser {
  id: string;
  email: string;
  tier: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export async function registerUser(email: string, password: string): Promise<{ token: string; user: { id: string; email: string; tier: string } }> {
  if (!email || !password || password.length < 6) {
    throw new Error('Email and password (min 6 chars) required');
  }
  const existing = getUserByEmail(email);
  if (existing) throw new Error('Email already registered');

  const hash = await bcrypt.hash(password, 10);
  const user = createUser(email, hash);
  const token = jwt.sign({ id: user.id, email: user.email, tier: user.tier }, JWT_SECRET, { expiresIn: '30d' });
  return { token, user };
}

export async function loginUser(email: string, password: string): Promise<{ token: string; user: { id: string; email: string; tier: string } }> {
  const user = getUserByEmail(email);
  if (!user) throw new Error('Invalid credentials');

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) throw new Error('Invalid credentials');

  const token = jwt.sign({ id: user.id, email: user.email, tier: user.tier }, JWT_SECRET, { expiresIn: '30d' });
  return { token, user: { id: user.id, email: user.email, tier: user.tier } };
}

export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthUser;
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function optionalAuth(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET) as AuthUser;
    } catch {}
  }
  next();
}
