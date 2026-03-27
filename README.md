# CodeHealth Report

**AI-Powered Codebase Audit as a Service**

*By [Versatech Ventures](https://versatechventures.com)*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What is CodeHealth?

CodeHealth scans any public GitHub repository and generates a comprehensive health report across **6 dimensions**:

| Dimension | What It Checks |
|-----------|---------------|
| 🔎 **Project Analysis** | Framework detection, tech stack, file structure, entry points |
| 🛡️ **Security** | Hardcoded secrets, eval usage, XSS vectors, injection patterns |
| 📦 **Dependencies** | npm audit vulnerabilities, outdated packages, dependency count |
| 📊 **Code Quality** | File sizes, TODO/FIXME density, console.log usage, deep nesting |
| 🧪 **Test Coverage** | Test file detection, coverage ratio, test runner identification |
| 📋 **Compliance** | License, README, .gitignore, .env handling, security headers |

## Features

- **6-Dimension Scanning** — Security, quality, dependencies, coverage, compliance, project structure
- **PDF Reports** — Professional downloadable reports (Pro tier)
- **Embeddable Badges** — `![CodeHealth](https://www.versatechventures.com/badge/owner/repo)`
- **Shareable Links** — Public report pages with OG metadata
- **JWT Authentication** — Register/login with email, per-user scan limits
- **SQLite Persistence** — Scan history and shared reports survive restarts
- **Rate Limiting** — Free tier: 3 scans/month, Pro: 10, Agency: unlimited

## Quick Start

```bash
# Install
npm install

# Build
npm run build

# Start
npm start
# → http://localhost:3500
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3500` | Server port |
| `JWT_SECRET` | Auto-generated | JWT signing secret |

## API Documentation

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | `{ email, password }` → `{ token, user }` |
| `POST` | `/api/auth/login` | `{ email, password }` → `{ token, user }` |
| `GET` | `/api/auth/me` | Requires `Authorization: Bearer <token>` |

### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | `{ repoUrl, branch? }` — Start scan |
| `GET` | `/api/status/:jobId` | Poll scan progress |
| `GET` | `/api/report/:jobId` | Download PDF (Pro+) |

### Sharing & Badges

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/share/:jobId` | Create shareable link |
| `GET` | `/share/:shareId` | View shared report |
| `GET` | `/badge/:owner/:repo` | SVG badge (24h cache) |

### Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/pricing` | Tier info |
| `GET` | `/api/health` | Server status |

## Architecture

```
src/
├── index.ts          # Express server, routes, middleware
├── scanner.ts        # Scan orchestrator
├── realScanner.ts    # 6-dimension analysis tools (execFileSync)
├── reporter.ts       # PDF report generator (Puppeteer + Handlebars)
├── database.ts       # SQLite persistence (better-sqlite3)
├── auth.ts           # JWT authentication (jsonwebtoken + bcryptjs)
└── types.ts          # TypeScript interfaces
```

## Tech Stack

- **Runtime:** Node.js + TypeScript
- **Server:** Express
- **Database:** SQLite (better-sqlite3)
- **Auth:** JWT + bcryptjs
- **PDF:** Puppeteer + Handlebars
- **Git:** simple-git
- **Analysis:** execFileSync (no shell injection)

## License

[MIT](LICENSE) © [Versatech Ventures](https://www.versatechventures.com)

## Contact

📧 contact@versatechventures.com
🌐 [www.versatechventures.com](https://www.versatechventures.com)
🐙 [github.com/VersatechVentures](https://github.com/VersatechVentures)
