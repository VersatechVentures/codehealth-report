# CodeHealth — Semantic Memory

> Auto-generated baseline. Updated by OpenClaw + NEXUS as the project evolves.
> Last updated: 2026-03-26 13:47 CDT

## Project Identity

- **Name:** CodeHealth Report
- **Version:** 0.3.0-demo (pre-launch)
- **Mission:** AI-powered codebase audit as a service — one URL, one PDF, professional report
- **Target:** Developers, freelancers, small teams who can't afford $10K+/yr Vanta/Drata/Snyk subscriptions
- **Pricing:** Free tier (3 scans/mo, web only) → Pro ($29/mo, PDF export) → Enterprise ($249/mo, API, SAML)
- **Differentiator:** Beautiful one-shot PDF audit report. No dashboards, no onboarding, no subscriptions required.

## Architecture

```
src/
├── index.ts        (403 lines) — Express server, API routes, scan orchestration
├── scanner.ts      (301 lines) — 6-tool scan pipeline (mock data in demo mode)
├── executive.ts    (269 lines) — Risk-first executive summary generator
├── reporter.ts     (157 lines) — Handlebars + Puppeteer PDF generation
├── types.ts        (109 lines) — Shared interfaces (Finding, ExecutiveSummary, Score, etc.)
├── scorer.ts       (106 lines) — Weighted scoring (Sec 40%, Deps 25%, Qual 20%, Maint 15%)
├── grouper.ts      (75 lines)  — CWE-based finding grouper (Top 25 + OWASP Top 10)
└── templates/
    └── report.html             — PDF template with executive summary + demo watermark
```

**Total:** 1,420 lines TypeScript + HTML template + landing page (786 lines)

### Module Dependency Graph

```
types.ts ← (foundation — no dependencies, everything imports from here)
    ↑
    ├── scorer.ts (imports: types)
    ├── grouper.ts (imports: types)
    ├── executive.ts (imports: types, scorer)
    ├── scanner.ts (imports: types) — uses grouper/scorer inline, owns mock data
    ├── reporter.ts (imports: types) — external: handlebars, puppeteer
    └── index.ts (imports: scanner, reporter, types) — external: express, cors, simple-git, uuid
```

**Critical path:** `index.ts → scanner.ts → types.ts` (scan request flow)
**PDF path:** `index.ts → reporter.ts → templates/report.html` (PDF generation)
**Scoring path:** `scanner.ts → scorer.ts + grouper.ts + executive.ts → types.ts`

**Design pattern:** Layered monolith. All modules are co-located in `src/`, no circular dependencies. `types.ts` is the shared contract layer — every module imports from it, nothing imports into it.

**Why this pattern:** MVP speed. A monolith with clean interfaces lets us ship fast while keeping the option to split into microservices later (scanner-as-service, reporter-as-service). The type layer ensures modules can be extracted without breaking contracts.

**What we rejected:** Microservices (premature for a 1,420-line codebase), monorepo with packages (overhead without benefit at this scale).

### Revenue Module → Source Code Mapping

| Module | Price | Source Files | Key Functions |
|---|---|---|---|
| Core: Scan Pipeline | Free tier | `index.ts`, `scanner.ts` | `scanRepo()`, `POST /api/scan` |
| Core: PDF Report | Pro ($29/mo) | `reporter.ts`, `templates/report.html` | `generatePDFReport()`, `GET /api/report/:jobId` |
| Core: Executive Summary | All tiers | `executive.ts` | `generateExecutiveSummary()` |
| Core: Scoring Engine | All tiers | `scorer.ts`, `grouper.ts` | `calculateScore()`, `groupFindings()` |
| Module 1: Self-Healing CI | $300/mo | NEXUS `tools.ts` | `ci_diagnose()`, `ci_auto_fix()` |
| Module 2: Test Generator | $50-250/mo | NEXUS `tools.ts` | `analyze_coverage()`, `test_and_fix()` |
| Module 3: Modernizer | $10K+/project | NEXUS `tools.ts` | `analyze_code_quality()`, `analyze_project()` |
| Module 4: Compliance | $100-500/mo | NEXUS `tools.ts` | `security_scan()`, `dependency_audit()`, `compliance_report()` |
| Module 5: DevOps | $250-1K/team | NEXUS `tools.ts` | `generate_dockerfile()`, `generate_ci_config()`, `scaffold_infrastructure()` |

### API Endpoints
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/scan` | POST | Free (rate-limited) | Trigger a repo scan |
| `/api/status/:jobId` | GET | None | Poll scan status |
| `/api/report/:jobId` | GET | Pro (`Bearer pro_*`) | Download PDF report |
| `/api/report/:jobId?test=true` | GET | Demo bypass | E2E test only |
| `/api/health` | GET | None | Health check |
| `/api/pricing` | GET | None | Pricing page |
| `/badge/:owner/:repo` | GET | None | Repo health badge |
| `/api/share/:jobId` | POST | None | Share report link |

### Tech Stack
- Runtime: Node.js + Express
- Language: TypeScript 5.3
- PDF: Handlebars templating → Puppeteer HTML-to-PDF
- Git: simple-git for repo cloning
- Testing: Jest + ts-jest (no tests written yet)

## Key Decisions (from adversarial debate)

### Scoring Weights — 4-Category (40/25/20/15)
- **Decided:** 2026-03-26
- **Debate:** NEXUS proposed 5-category (35/25/15/10/15) including coverage and compliance
- **Outcome:** Shipped 4-category because coverage/compliance aren't first-class scored inputs yet
- **Rationale:** False precision worse than honest simplicity. Enterprise hard gate preserves security dominance.
- **Counter-argument (NEXUS):** 5-category better reflects enterprise compliance needs. Coverage signals testing maturity. Compliance signals regulatory readiness.
- **What we lost:** Granularity for enterprise buyers who want to see coverage/compliance as separate scored dimensions. May need to revisit when selling to compliance-focused customers.
- **Revisit when:** `scanner.ts` produces structured coverage + compliance scores (not raw text extraction)

### Executive Summary — Risk-First, No Effort Estimates
- **Decided:** 2026-03-26
- **Debate:** Original had `estimatedEffort` field. NEXUS demanded removal.
- **Outcome:** Replaced with Low/Medium/High complexity indicator. Zero dollar or time estimates.
- **Rationale:** Effort estimates create liability and false precision. DryRun's 2025 report showed pattern-matching tools miss logic flaws entirely — false confidence is dangerous.
- **Counter-argument (NEXUS):** Dollar estimates could be a selling point ("this tool just saved you $50K in audit costs"). Removal weakens the value prop for budget-conscious buyers.
- **What we lost:** A quantifiable ROI story. Harder to justify the subscription price without "saved you X hours."
- **Revisit when:** We have real scan data + customer feedback on whether they want estimates. Could offer as opt-in with heavy disclaimers.

### Demo Watermarking — Permanent, Non-Removable
- **Decided:** 2026-03-26
- **Debate:** NEXUS flagged mock data as professional negligence risk
- **Outcome:** All demo reports get `[SAMPLE DATA — NOT A REAL SCAN]` banner + diagonal "DEMO MODE" overlay
- **Rationale:** No mixing mock + real in any user-facing context. Period.
- **Counter-argument:** None. This was unanimous. Professional negligence risk with zero upside to removing it.
- **What we lost:** Nothing. Clean win.

### Finding Grouper — CWE-Based, Not ML
- **Decided:** 2026-03-26
- **Debate:** NEXUS pushed for ML classification. OpenClaw defended keyword expansion for MVP.
- **Outcome:** CWE ID-based grouping (deterministic, standards-based). ML deferred to Phase 5+.
- **Rationale:** Debate-001 principle — MVP constraints apply. ML is overkill when CWE Top 25 + OWASP Top 10 covers ~80% of findings.
- **Counter-argument (NEXUS):** CWE mapping misses findings without CWE IDs (quality issues, style violations, custom rules). ML could classify these into meaningful groups.
- **What we lost:** Ability to group non-CWE findings intelligently. The "Ungrouped" bucket will grow as we add more scan tools.
- **Revisit when:** Ungrouped bucket exceeds 20% of total findings in real scans

## Technical Debt

| Item | Files Affected | Trigger to Revisit | Trade-off |
|---|---|---|---|
| No unit tests for reporter.ts | 1 file, ~157 lines | Before any template change | Chose to test pure logic first (scorer/grouper/executive). Reporter requires Puppeteer mocking — slower ROI. |
| No integration/API tests | index.ts (403 lines) | Before adding any new endpoint | Tested E2E manually. Automated API tests needed when endpoint count > 5. |
| Mock scanner data | scanner.ts (301 lines) | When NEXUS bridge tools are production-ready | Real scanning requires `simple-git` clone + tool execution. Mock lets us validate everything else first. |
| In-memory job store | index.ts (Map<string, ScanJob>) | When concurrent users > 10 OR server restarts lose data in testing | Redis or SQLite. Current Map works for demo/dev. |
| No authentication | index.ts (paywall check is `Bearer pro_*` prefix) | Before accepting real payments | Need Stripe + JWT. Current check is placeholder. |
| 5-category scoring deferred | scorer.ts | When `scanner.ts` produces structured coverage + compliance scores (not raw text) | 4-category is honest — we don't score what we don't measure. |
| Badge caching | index.ts badge endpoint | When badge requests > 100/day | SVG regenerates every request. CDN or Redis cache. |
| CWE case-insensitivity | grouper.ts (exact match on CWE_CATEGORIES keys) | Before processing real scan output (tools may return lowercase) | One-line fix: normalize to uppercase before lookup. |

## Competitive Position

### We Win On
- **One-shot PDF** — nobody else does this. Competitors require subscriptions + dashboards.
- **Price** — $29/mo vs $10K+/yr (Vanta, Drata, Snyk enterprise)
- **Simplicity** — one URL in, one PDF out. No onboarding.

### We Lose On
- **Depth** — mock data; real scanning not yet implemented
- **Trust** — no customers, no testimonials, no track record
- **Enterprise features** — no SAML, no API, no team management

### Key Competitors
| Player | Price | Our Advantage |
|---|---|---|
| SonarQube | Self-hosted (free) + Cloud ($15K+/yr) | We're SaaS-first, no infra needed |
| Snyk | $25-300/mo | We do full-stack audit, not just SCA |
| Vanta | $10K-50K/yr | We're 100x cheaper for SMBs |
| GitGuard.net | Free | We generate professional PDF reports |
| CodeAnt AI | $15-50/mo | We target freelancers + agencies, not just teams |

## Revenue Modules (Built into NEXUS)

| Module | Price Target | Status |
|---|---|---|
| 1. Self-Healing CI/CD | $300/mo/team | Tools ready, not productized |
| 2. AI Test Suite Generator | $50-250/mo/repo | Tools ready, not productized |
| 3. Legacy Code Modernizer | $10K+/project | Tools ready, not productized |
| 4. Compliance Auditor | $100-500/mo | Scanner pipeline working |
| 5. DevOps Playbook Generator | $250-1K/team | Tools ready, not productized |

## Phase History

| Phase | Status | Completed |
|---|---|---|
| 1. Bridge Hardening | ✅ Complete | 2026-03-23 |
| 2. Discord Integration | ✅ Complete | 2026-03-24 |
| 3. Autonomous Task Pipeline | ✅ Complete + Validated | 2026-03-26 |
| 4. Intelligence & Memory Layer | 🟡 In Progress | — |
| 5. Revenue & Orchestration | ⬜ Not Started | — |
