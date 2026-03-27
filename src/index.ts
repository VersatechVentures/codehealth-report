import express from "express";
import cors from "cors";
import path from "path";
import os from "os";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import simpleGit from "simple-git";
import { scanRepo } from "./scanner";
import { generatePDFReport } from "./reporter";
import { ScanJob, ScanRequest, CodeHealthReport } from "./types";
import { initDB, saveJob as dbSaveJob, getJob as dbGetJob, saveSharedReport as dbSaveShared, getSharedReport as dbGetShared, getUserById, incrementScanCount } from "./database";
import { registerUser, loginUser, authenticateToken, optionalAuth } from "./auth";

const app = express();

// ═══════════════════════════════════════════
// INPUT VALIDATION
// ═══════════════════════════════════════════
const GITHUB_REPO_RE = /^https:\/\/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)\/?$/;

function isValidGitHubUrl(url: string): boolean {
  return GITHUB_REPO_RE.test(url.replace(/\.git$/, ''));
}

function isValidOwnerRepo(owner: string, repo: string): boolean {
  const valid = /^[a-zA-Z0-9_.-]+$/;
  return valid.test(owner) && valid.test(repo) && !owner.includes('..') && !repo.includes('..');
}
const PORT = parseInt(process.env.PORT || "3500", 10);

// In-memory stores (MVP — replace with DB later)
const jobs = new Map<string, ScanJob>();
const badgeCache = new Map<string, { svg: string; expires: number }>();
const sharedReports = new Map<string, { report: CodeHealthReport; createdAt: string }>();

// ═══════════════════════════════════════════
// RATE LIMITER — Free tier: 3 scans/month
// ═══════════════════════════════════════════
const FREE_SCAN_LIMIT = 3;
const scanUsage = new Map<string, { count: number; resetDate: string }>();

function getClientIp(req: express.Request): string {
  const forwarded = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim();
  const ip = forwarded || req.ip || "unknown";
  // Normalize IPv6 localhost to IPv4
  return ip === "::1" || ip === "::ffff:127.0.0.1" ? "127.0.0.1" : ip;
}

function checkRateLimit(req: express.Request): { allowed: boolean; remaining: number; resetDate: string } {
  const ip = getClientIp(req);
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  const resetDate = nextMonth.toISOString();
  const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  
  // Check for Pro token (future Stripe integration)
  const authToken = req.headers.authorization;
  if (authToken?.startsWith("Bearer pro_")) {
    return { allowed: true, remaining: 999, resetDate };
  }

  let usage = scanUsage.get(ip);
  // Reset if new month
  if (!usage || usage.resetDate !== monthKey) {
    usage = { count: 0, resetDate: monthKey };
    scanUsage.set(ip, usage);
  }

  if (usage.count >= FREE_SCAN_LIMIT) {
    return { allowed: false, remaining: 0, resetDate: resetDate };
  }

  usage.count++;
  const remaining = FREE_SCAN_LIMIT - usage.count;
  console.log(`[RateLimit] IP=${ip} count=${usage.count}/${FREE_SCAN_LIMIT} remaining=${remaining}`);
  return { allowed: true, remaining, resetDate: resetDate };
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

// ═══════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await registerUser(email, password);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await loginUser(email, password);
    res.json(result);
  } catch (err: any) {
    res.status(401).json({ error: err.message });
  }
});

app.get("/api/auth/me", authenticateToken, (req, res) => {
  const user = getUserById(req.user!.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({
    id: user.id,
    email: user.email,
    tier: user.tier,
    scansThisMonth: user.scans_this_month,
    scansResetDate: user.scans_reset_date,
  });
});

// ═══════════════════════════════════════════
// PRICING INFO
// ═══════════════════════════════════════════

/** GET /api/pricing — Tier information */
app.get("/api/pricing", (_req, res) => {
  res.json({
    tiers: [
      { name: "Free", price: 0, scansPerMonth: 3, features: ["Public repos", "Web report", "Badge access", "Share links"] },
      { name: "Pro", price: 29, scansPerMonth: 10, features: ["Private repos", "PDF export", "Full 6-dimension audit", "Scan history"] },
      { name: "Agency", price: 99, scansPerMonth: -1, features: ["Unlimited scans", "White-label PDFs", "Client portal", "Custom branding", "Priority support"] },
    ],
  });
});

// ═══════════════════════════════════════════
// CORE API — Scan, Status, PDF
// ═══════════════════════════════════════════

/** POST /api/scan — Start a new codebase scan (rate-limited) */
app.post("/api/scan", optionalAuth, async (req, res) => {
  const { repoUrl, branch } = req.body as ScanRequest;

  if (!repoUrl || !isValidGitHubUrl(repoUrl)) {
    return res.status(400).json({ error: "Valid GitHub repo URL required (https://github.com/owner/repo)" });
  }

  // Rate limit check
  const limit = checkRateLimit(req);
  if (!limit.allowed) {
    return res.status(429).json({
      error: "Free scan limit reached",
      message: `You've used all ${FREE_SCAN_LIMIT} free scans this month. Upgrade to Pro for 10 scans/month.`,
      remaining: 0,
      resetDate: limit.resetDate,
      upgradeUrl: "/api/pricing",
    });
  }

  const jobId = uuidv4();
  const job: ScanJob = {
    id: jobId,
    status: "queued",
    repoUrl,
    createdAt: new Date().toISOString(),
  };
  jobs.set(jobId, job);
  dbSaveJob({ id: jobId, user_id: req.user?.id, repo_url: repoUrl, status: "queued" });
  if (req.user) incrementScanCount(req.user.id);

  // Run scan async
  (async () => {
    try {
      job.status = "cloning";
      const tmpDir = path.join(os.tmpdir(), `codehealth-${jobId}`);
      const git = simpleGit();
      await git.clone(repoUrl, tmpDir, ["--depth", "1", ...(branch ? ["--branch", branch] : [])]);

      job.status = "scanning";
      const report = await scanRepo(tmpDir, repoUrl);

      job.status = "complete";
      job.completedAt = new Date().toISOString();
      job.report = report;
      dbSaveJob({ id: jobId, repo_url: repoUrl, status: "complete", report, completed_at: job.completedAt });

      console.log(`[Server] Job ${jobId} complete: ${report.summary.grade}`);

      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err: any) {
      job.status = "failed";
      job.error = err.message;
      dbSaveJob({ id: jobId, repo_url: repoUrl, status: "failed", error: err.message });
      console.error(`[Server] Job ${jobId} failed:`, err.message);
    }
  })();

  res.json({ jobId, status: "queued", message: "Scan started. Poll /api/status/:jobId for results.", scansRemaining: limit.remaining });
});

/** GET /api/status/:jobId — Check scan progress */
app.get("/api/status/:jobId", (req, res) => {
  const job = jobs.get(req.params.jobId) || dbGetJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }
  res.json(job);
});

/** GET /api/report/:jobId — Download PDF report (Pro+ only) */
app.get("/api/report/:jobId", async (req, res) => {
  const job = jobs.get(req.params.jobId) || dbGetJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }
  if (job.status !== "complete" || !job.report) {
    return res.status(400).json({ error: "Report not ready. Job status: " + job.status });
  }

  // Check for Pro auth (future Stripe integration)
  // Test bypass: ?test=true skips paywall in demo mode for E2E testing
  const isTestBypass = req.query.test === "true"; // Allow test bypass in all modes for now
  const authToken = req.headers.authorization;
  if (!isTestBypass && !authToken?.startsWith("Bearer pro_")) {
    return res.status(402).json({
      error: "PDF export requires Pro plan",
      message: "Upgrade to Pro ($29/mo) to download professional PDF reports. Free users can view reports on the web and share via link.",
      upgradeUrl: "/api/pricing",
      alternativeUrl: `/share/${req.params.jobId}`,
    });
  }
  try {
    const pdfBuffer = await generatePDFReport(job.report);
    const filename = `codehealth-${job.report.meta.repoName.replace(/[^a-zA-Z0-9]/g, '-')}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(pdfBuffer);
  } catch (err: any) {
    console.error(`[Server] PDF generation failed for job ${req.params.jobId}:`, err.message);
    res.status(500).json({ error: "Failed to generate PDF report" });
  }
});

// ═══════════════════════════════════════════
// FEATURE 1: BADGE ENDPOINT (Viral Loop)
// GET /badge/:owner/:repo → Cached SVG badge
// Embed: ![CodeHealth](https://codehealth.dev/badge/owner/repo)
// ═══════════════════════════════════════════

function generateBadgeSvg(score: number, grade: string): string {
  const gradeColors: Record<string, string> = {
    A: "#22C55E", B: "#84CC16", C: "#F59E0B", D: "#F97316", F: "#EF4444",
  };
  const color = gradeColors[grade] || "#64748B";
  const labelWidth = 72;
  const valueText = `${score}/100 ${grade}`;
  const valueWidth = 8 * valueText.length + 16;
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="CodeHealth: ${valueText}">
  <title>CodeHealth: ${valueText}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#1E293B"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-rendering="geometricPrecision">
    <text x="${labelWidth / 2}" y="14" fill="#fff">CodeHealth</text>
    <text x="${labelWidth + valueWidth / 2}" y="14" fill="#fff" font-weight="bold">${valueText}</text>
  </g>
</svg>`;
}

/** GET /badge/:owner/:repo — SVG badge with 24h cache */
app.get("/badge/:owner/:repo", async (req, res) => {
  const { owner, repo } = req.params;

  if (!isValidOwnerRepo(owner, repo)) {
    return res.status(400).json({ error: "Invalid owner/repo" });
  }

  const cacheKey = `${owner}/${repo}`;
  const now = Date.now();

  // Check cache (24h TTL)
  const cached = badgeCache.get(cacheKey);
  if (cached && cached.expires > now) {
    res.setHeader("Content-Type", "image/svg+xml");
    res.setHeader("Cache-Control", "public, max-age=86400");
    return res.send(cached.svg);
  }

  try {
    // Run a scan
    const repoUrl = `https://github.com/${owner}/${repo}`;
    const tmpDir = path.join(os.tmpdir(), `badge-${owner}-${repo}-${now}`);
    const git = simpleGit();
    await git.clone(repoUrl, tmpDir, ["--depth", "1"]);
    const report = await scanRepo(tmpDir, repoUrl);

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });

    // Generate and cache SVG
    const svg = generateBadgeSvg(report.summary.overallScore, report.summary.grade);
    badgeCache.set(cacheKey, { svg, expires: now + 86400000 }); // 24h

    res.setHeader("Content-Type", "image/svg+xml");
    res.setHeader("Cache-Control", "public, max-age=86400");
    res.send(svg);

    console.log(`[Badge] ${cacheKey}: ${report.summary.overallScore}/${report.summary.grade}`);
  } catch (err: any) {
    // Return a "scan failed" badge
    const svg = generateBadgeSvg(0, "?");
    res.setHeader("Content-Type", "image/svg+xml");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.send(svg);
    console.error(`[Badge] ${cacheKey} failed:`, err.message);
  }
});

// ═══════════════════════════════════════════
// FEATURE 2: SHAREABLE REPORT PAGES
// POST /api/share/:jobId → Create public share link
// GET /share/:shareId → View shared report (HTML)
// ═══════════════════════════════════════════

/** POST /api/share/:jobId — Create a shareable link for a completed scan */
app.post("/api/share/:jobId", (req, res) => {
  const job = jobs.get(req.params.jobId) || dbGetJob(req.params.jobId);
  if (!job || job.status !== "complete" || !job.report) {
    return res.status(400).json({ error: "No completed report found for this job" });
  }

  const shareId = uuidv4().slice(0, 12);
  sharedReports.set(shareId, {
    report: job.report,
    createdAt: new Date().toISOString(),
  });
  dbSaveShared(shareId, req.params.jobId, job.report);

  const shareUrl = `${req.protocol}://${req.get("host")}/share/${shareId}`;
  res.json({ shareId, shareUrl, message: "Report shared successfully" });
  console.log(`[Share] Created: ${shareUrl} for ${job.report.meta.repoName}`);
});

/** GET /share/:shareId — Public shareable report page */
app.get("/share/:shareId", (req, res) => {
  let shared = sharedReports.get(req.params.shareId);
  if (!shared) {
    const dbRow = dbGetShared(req.params.shareId);
    if (dbRow) shared = { report: dbRow.report, createdAt: dbRow.created_at };
  }
  if (!shared) {
    return res.status(404).send("Report not found or expired.");
  }

  const r = shared.report;
  const gradeColors: Record<string, string> = {
    A: "#22C55E", B: "#84CC16", C: "#F59E0B", D: "#F97316", F: "#EF4444",
  };
  const gradeColor = gradeColors[r.summary.grade] || "#64748B";

  // Inline HTML report — branded, read-only, shareable
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CodeHealth Report: ${r.meta.repoName} — ${r.summary.overallScore}/100</title>
  <meta property="og:title" content="CodeHealth: ${r.meta.repoName} scored ${r.summary.overallScore}/100 (${r.summary.grade})">
  <meta property="og:description" content="AI-powered codebase audit by Versatech Ventures. Security, quality, dependencies, coverage, and compliance.">
  <meta name="twitter:card" content="summary">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Fira+Code:wght@400&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0F172A; --surface:#1B2336; --border:rgba(71,85,105,0.3); --text:#F8FAFC; --muted:#94A3B8; --grade:${gradeColor}; }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Inter',sans-serif; background:var(--bg); color:var(--text); line-height:1.6; padding:32px 16px; }
    .container { max-width:800px; margin:0 auto; }
    .header { text-align:center; margin-bottom:40px; }
    .score-circle { width:100px; height:100px; border-radius:50%; border:4px solid var(--grade); display:inline-grid; place-items:center; font-size:2rem; font-weight:800; margin:16px 0; }
    .grade { font-size:1.2rem; font-weight:700; color:var(--grade); }
    .risk { display:inline-block; padding:4px 12px; border-radius:99px; font-size:0.75rem; font-weight:600; text-transform:uppercase; background:rgba(71,85,105,0.2); margin-top:8px; }
    .meta { font-size:0.82rem; color:var(--muted); margin-top:12px; }
    .section { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:16px; }
    .section h3 { font-size:1rem; margin-bottom:12px; display:flex; align-items:center; gap:8px; }
    .section pre { font-family:'Fira Code',monospace; font-size:0.78rem; color:var(--muted); white-space:pre-wrap; line-height:1.7; max-height:300px; overflow-y:auto; }
    .cta { text-align:center; margin-top:40px; padding:32px; background:var(--surface); border:1px solid var(--border); border-radius:12px; }
    .cta a { display:inline-block; padding:12px 28px; background:#6366F1; color:#fff; text-decoration:none; border-radius:10px; font-weight:600; }
    .cta a:hover { background:#4F46E5; }
    .cta p { color:var(--muted); font-size:0.85rem; margin-top:10px; }
    .branding { text-align:center; margin-top:32px; font-size:0.75rem; color:var(--muted); }
    .branding a { color:#818CF8; text-decoration:none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${r.meta.repoName}</h1>
      <div class="score-circle">${r.summary.overallScore}</div>
      <div class="grade">Grade ${r.summary.grade}</div>
      <div class="risk">${r.summary.riskLevel} risk</div>
      <p class="meta">Scanned ${new Date(r.meta.scanDate).toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' })} &middot; ${r.meta.scanDurationMs}ms</p>
    </div>

    <div class="section"><h3>🔎 Project Overview</h3><pre>${escapeHtml(r.sections.project.raw)}</pre></div>
    <div class="section"><h3>🛡️ Security Analysis</h3><pre>${escapeHtml(r.sections.security.raw)}</pre></div>
    <div class="section"><h3>📦 Dependency Audit</h3><pre>${escapeHtml(r.sections.dependencies.raw)}</pre></div>
    <div class="section"><h3>📊 Code Quality</h3><pre>${escapeHtml(r.sections.quality.raw)}</pre></div>
    <div class="section"><h3>🧪 Test Coverage</h3><pre>${escapeHtml(r.sections.coverage.raw)}</pre></div>
    <div class="section"><h3>📋 Compliance</h3><pre>${escapeHtml(r.sections.compliance.raw)}</pre></div>

    <div class="cta">
      <p style="font-size:1.1rem;font-weight:600;color:var(--text);margin-bottom:8px;">Want your own CodeHealth report?</p>
      <a href="/">Scan Your Repo Free →</a>
      <p>AI-powered codebase audits in under 60 seconds</p>
    </div>

    <div class="branding">
      Powered by <a href="/">CodeHealth</a> &middot; <a href="https://versatechventures.com">Versatech Ventures</a>
    </div>
  </div>
</body>
</html>`;

  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ═══════════════════════════════════════════
// HEALTH + STARTUP
// ═══════════════════════════════════════════

/** GET /api/health — Server health */
app.get("/api/health", (_req, res) => {
  res.json({
    status: "online",
    service: "CodeHealth Report",
    version: "0.3.0",
    jobs: jobs.size,
    badges: badgeCache.size,
    shares: sharedReports.size,
    freeTierLimit: FREE_SCAN_LIMIT,
  });
});

// Initialize database
initDB();

app.listen(PORT, () => {
  console.log(`\n🔬 CodeHealth Report v0.3.0 — Revenue Engine`);
  console.log(`   Landing:  http://localhost:${PORT}/`);
  console.log(`   Scan:     POST http://localhost:${PORT}/api/scan`);
  console.log(`   Badge:    GET  http://localhost:${PORT}/badge/:owner/:repo`);
  console.log(`   Share:    POST http://localhost:${PORT}/api/share/:jobId`);
  console.log(`   Pricing:  GET  http://localhost:${PORT}/api/pricing`);
  console.log(`   Health:   GET  http://localhost:${PORT}/api/health`);
  console.log(`   Free tier: ${FREE_SCAN_LIMIT} scans/month | PDF: Pro only\n`);
});
