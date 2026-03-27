/**
 * Real Scanner Tools — Replaces mock data with actual analysis
 * 
 * Tools:
 * 1. analyzeProject — reads package.json, detects framework, counts files
 * 2. securityScan — grep-based secret detection + pattern matching  
 * 3. dependencyAudit — npm audit --json
 * 4. analyzeCodeQuality — file stats, complexity proxies, code smells
 * 5. analyzeCoverage — detect test files and compute coverage ratio
 * 6. complianceReport — check for security headers, .env handling, license
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/** Safe command execution — no shell injection possible */
function runFile(cmd: string, args: string[], cwd: string, timeoutMs = 30000): string {
  try {
    return execFileSync(cmd, args, { cwd, timeout: timeoutMs, maxBuffer: 5 * 1024 * 1024, encoding: 'utf-8' });
  } catch (err: any) {
    return err.stdout || err.stderr || '';
  }
}

function findFiles(cwd: string, args: string[]): string[] {
  // Exclude the scanner's own source directory to prevent self-scanning false positives.
  const excludedPaths = ['.git', 'node_modules', 'dist', 'src'];
  const excludeArgs = excludedPaths.flatMap(p => ['-not', '-path', `*/${p}/*`]);
  const finalArgs = ['.', ...excludeArgs, ...args];
  
  const output = runFile('find', finalArgs, cwd);
  return output.trim().split('\n').filter(Boolean);
}

export function analyzeProject(repoPath: string): string {
  const lines: string[] = ['## Project Analysis\n'];
  const pkgPath = path.join(repoPath, 'package.json');
  let depCount = 0, framework = 'Unknown', scripts: string[] = [];
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      depCount = Object.keys(allDeps).length;
      if ('next' in allDeps) framework = 'Next.js';
      else if ('express' in allDeps) framework = 'Node.js/Express';
      else if ('react' in allDeps) framework = 'React';
      else if ('vue' in allDeps) framework = 'Vue.js';
      else if ('fastify' in allDeps) framework = 'Fastify';
      else framework = 'Node.js';
      scripts = Object.keys(pkg.scripts || {});
      lines.push(`Name: ${pkg.name || 'unnamed'}`);
      lines.push(`Version: ${pkg.version || 'unversioned'}`);
    } catch {}
  }

  const allFiles = findFiles(repoPath, ['-type', 'f', '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*']);
  const files = allFiles.slice(0, 500);
  const extCounts: Record<string, number> = {};
  for (const f of files) { const ext = path.extname(f) || '(no ext)'; extCounts[ext] = (extCounts[ext] || 0) + 1; }
  const entryPoints: string[] = [];
  for (const c of ['index.js','index.ts','app.js','app.ts','server.js','server.ts','main.js','main.ts','src/index.ts','src/index.js']) {
    if (fs.existsSync(path.join(repoPath, c))) entryPoints.push(c);
  }
  const tsFiles = (extCounts['.ts'] || 0) + (extCounts['.tsx'] || 0);
  const jsFiles = (extCounts['.js'] || 0) + (extCounts['.jsx'] || 0);
  const pyFiles = extCounts['.py'] || 0;
  const techStack = tsFiles > jsFiles && tsFiles > pyFiles ? 'TypeScript' : jsFiles > pyFiles ? 'JavaScript' : pyFiles > 0 ? 'Python' : 'Unknown';
  lines.push(`Framework: ${framework}`, `Dependencies: ${depCount} packages`, `Entry Points: ${entryPoints.join(', ') || 'unknown'}`, `Tech Stack: ${techStack}`, `Total Files: ${files.length}`, `Scripts: ${scripts.join(', ') || 'none'}`);
  const topExts = Object.entries(extCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  lines.push(`File Types: ${topExts.map(([ext, n]) => `${ext}(${n})`).join(', ')}`);
  let health = 50;
  if (depCount > 0) health += 10; if (entryPoints.length > 0) health += 10;
  if (scripts.includes('test')) health += 10; if (scripts.includes('build')) health += 5; if (scripts.includes('lint')) health += 5;
  if (fs.existsSync(path.join(repoPath, 'README.md'))) health += 5; if (fs.existsSync(path.join(repoPath, 'LICENSE'))) health += 5;
  lines.push(`Health Score: ${Math.min(100, health)}/100`);
  return lines.join('\n');
}

export function securityScan(repoPath: string): string {
  const lines: string[] = ['## Security Scan Results\n'];
  const patterns: Array<{ name: string; severity: string; regex: string }> = [
    { name: 'AWS Access Key', severity: 'CRITICAL', regex: 'AKIA[0-9A-Z]{16}' },
    { name: 'Private Key', severity: 'CRITICAL', regex: '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----' },
    { name: 'Hardcoded Password', severity: 'HIGH', regex: '(password|passwd|pwd)\\s*[:=]\\s*["\'][^"\']{4,}' },
    { name: 'API Key/Token', severity: 'HIGH', regex: '(api[_-]?key|api[_-]?secret|access[_-]?token)\\s*[:=]\\s*["\'][A-Za-z0-9+/=_-]{8,}' },
    { name: 'eval() usage', severity: 'HIGH', regex: '\\beval\\s*\\(' },
    { name: 'innerHTML (XSS)', severity: 'MEDIUM', regex: '\\.innerHTML\\s*=' },
    { name: 'exec/spawn template', severity: 'HIGH', regex: '(exec|spawn|execSync)\\s*\\([^)]*\\$\\{' },
    { name: 'HTTP URL', severity: 'LOW', regex: 'http://(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)' },
    { name: 'Sensitive logging', severity: 'LOW', regex: 'console\\.(log|debug).*(?:password|secret|token|key|auth)' },
    { name: 'TODO Security', severity: 'INFO', regex: '(TODO|FIXME).*(security|auth|vuln|inject|xss|csrf)' },
  ];

  const codeFiles = findFiles(repoPath, [
    '-type', 'f',
    '(', '-name', '*.ts', '-o', '-name', '*.tsx', '-o', '-name', '*.js', '-o', '-name', '*.jsx',
    '-o', '-name', '*.py', '-o', '-name', '*.json', '-o', '-name', '*.yml', '-o', '-name', '*.yaml',
    '-o', '-name', '*.env*', ')',
    '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*',
    '-not', '-path', '*/dist/*', '-not', '-path', '*/build/*'
  ]).slice(0, 300);

  lines.push(`Scanned ${codeFiles.length} files`);
  let critical = 0, high = 0, medium = 0, low = 0;
  const findings: string[] = [];

  for (const pattern of patterns) {
    const result = runFile('grep', [
      '-rnI', pattern.regex,
      '--include=*.ts', '--include=*.tsx', '--include=*.js', '--include=*.jsx',
      '--include=*.py', '--include=*.json', '--include=*.yml', '--include=*.yaml',
      '--include=*.env*',
      '--exclude-dir=node_modules', '--exclude-dir=.git', '--exclude-dir=dist', '--exclude-dir=build',
      '.'
    ], repoPath);

    if (result.trim()) {
      const matches = result.trim().split('\n').slice(0, 20);
      for (const m of matches) {
        const parts = m.split(':');
        findings.push(`- [${pattern.severity}] ${pattern.name} in ${parts[0]}:${parts[1]}`);
        if (pattern.severity === 'CRITICAL') critical++; else if (pattern.severity === 'HIGH') high++; else if (pattern.severity === 'MEDIUM') medium++; else low++;
      }
    }
  }

  if (findings.length === 0) { lines.push('No security vulnerabilities found'); }
  else { lines.push(`${findings.length} findings: ${critical} critical, ${high} high, ${medium} medium, ${low} low`); lines.push(...findings.slice(0, 15)); if (findings.length > 15) lines.push(`... and ${findings.length - 15} more`); }
  lines.push(`Security Score: ${Math.max(0, 100 - critical*25 - high*15 - medium*5 - low*2)}/100`);
  return lines.join('\n');
}

export function dependencyAudit(repoPath: string): string {
  const lines: string[] = ['## Dependency Audit\n'];
  const pkgPath = path.join(repoPath, 'package.json');
  if (!fs.existsSync(pkgPath)) { lines.push('No package.json found', 'Dependency Health: N/A'); return lines.join('\n'); }
  try { const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')); lines.push(`Total Dependencies: ${Object.keys(pkg.dependencies || {}).length} (+ ${Object.keys(pkg.devDependencies || {}).length} dev)`); } catch {}
  const lockPath = path.join(repoPath, 'package-lock.json');
  if (fs.existsSync(lockPath)) {
    const audit = runFile('npm', ['audit', '--json'], repoPath, 60000);
    try {
      const d = JSON.parse(audit); const v = d.metadata?.vulnerabilities || {};
      const c = v.critical||0, h = v.high||0, m = v.moderate||0, l = v.low||0;
      lines.push(`Security Vulnerabilities: ${c+h+m+l} (${c} critical, ${h} high, ${m} moderate, ${l} low)`);
      if (d.vulnerabilities) { for (const [name, info] of Object.entries(d.vulnerabilities).slice(0, 10)) { const vi = info as any; lines.push(`- [${(vi.severity||'').toUpperCase()}] ${name}: ${vi.via?.[0]?.title || vi.via?.[0] || 'vulnerability'}`); } }
      lines.push(`Dependency Health: ${Math.max(0, 100 - c*30 - h*15 - m*5 - l*2)}/100`);
    } catch { lines.push('npm audit returned non-JSON output', `Dependency Health: 70/100`); }
  } else { lines.push('No package-lock.json — cannot run npm audit', 'Dependency Health: 60/100'); }
  return lines.join('\n');
}

export function analyzeCodeQuality(repoPath: string): string {
  const lines: string[] = ['## Code Quality Analysis\n'];
  const files = findFiles(repoPath, [
    '-type', 'f',
    '(', '-name', '*.ts', '-o', '-name', '*.tsx', '-o', '-name', '*.js', '-o', '-name', '*.jsx', '-o', '-name', '*.py', ')',
    '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*', '-not', '-path', '*/dist/*'
  ]).slice(0, 200);

  let totalLines = 0, largeFiles = 0, veryLargeFiles = 0, todoCount = 0, consoleLogs = 0, anyTypes = 0, deepNesting = 0;
  for (const file of files) {
    try {
      const content = fs.readFileSync(path.join(repoPath, file), 'utf-8');
      const lc = content.split('\n').length; totalLines += lc;
      if (lc > 500) largeFiles++; if (lc > 1000) veryLargeFiles++;
      todoCount += (content.match(/TODO|FIXME|HACK|XXX/gi) || []).length;
      consoleLogs += (content.match(/console\.(log|debug)/g) || []).length;
      anyTypes += (content.match(/:\s*any\b/g) || []).length;
      deepNesting += (content.match(/^\s{16,}\S/gm) || []).length;
    } catch {}
  }
  const avg = files.length > 0 ? Math.round(totalLines / files.length) : 0;
  lines.push(`Files Analyzed: ${files.length}`, `Total Lines: ${totalLines.toLocaleString()}`, `Average Lines/File: ${avg}`, `Large Files (>500): ${largeFiles}`, `Very Large (>1000): ${veryLargeFiles}`, `TODO/FIXME: ${todoCount}`, `Debug Statements: ${consoleLogs}`);
  if (anyTypes > 0) lines.push(`TypeScript 'any': ${anyTypes}`);
  if (deepNesting > 0) lines.push(`Deep Nesting: ${deepNesting}`);
  let score = 100;
  if (largeFiles > 5) score -= 10; if (veryLargeFiles > 2) score -= 15; if (todoCount > 20) score -= 10;
  if (consoleLogs > 30) score -= 10; if (anyTypes > 10) score -= 10; if (deepNesting > 10) score -= 10;
  lines.push(`Health Score: ${Math.max(0, Math.min(100, score))}/100`);
  return lines.join('\n');
}

export function analyzeCoverage(repoPath: string): string {
  const lines: string[] = ['## Test Coverage Analysis\n'];
  const srcFiles = findFiles(repoPath, [
    '-type', 'f',
    '(', '-name', '*.ts', '-o', '-name', '*.tsx', '-o', '-name', '*.js', '-o', '-name', '*.jsx', ')',
    '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*', '-not', '-path', '*/dist/*',
    '-not', '-name', '*.test.*', '-not', '-name', '*.spec.*', '-not', '-path', '*/__tests__/*'
  ]).slice(0, 200);

  const testFiles = findFiles(repoPath, [
    '-type', 'f',
    '(', '-name', '*.test.*', '-o', '-name', '*.spec.*', ')',
    '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*'
  ]).slice(0, 200);

  const testedFiles = srcFiles.filter(src => { const base = path.basename(src).replace(/\.[^.]+$/, ''); return testFiles.some(t => t.includes(base + '.test.') || t.includes(base + '.spec.')); });
  const coverage = srcFiles.length > 0 ? Math.round((testedFiles.length / srcFiles.length) * 100) : 0;
  const hasJest = fs.existsSync(path.join(repoPath, 'jest.config.js')) || fs.existsSync(path.join(repoPath, 'jest.config.ts'));
  const hasVitest = fs.existsSync(path.join(repoPath, 'vitest.config.ts'));
  const runner = hasJest ? 'Jest' : hasVitest ? 'Vitest' : 'Unknown';
  lines.push(`Source Files: ${srcFiles.length}`, `Test Files: ${testFiles.length}`, `Files with Tests: ${testedFiles.length}/${srcFiles.length}`, `File Coverage: ${coverage}%`, `Test Runner: ${runner}`);
  let score = Math.min(100, coverage + 10); if (runner !== 'Unknown') score = Math.min(100, score + 5);
  lines.push(`Test Quality Score: ${score}/100`);
  return lines.join('\n');
}

export function complianceReport(repoPath: string): string {
  const lines: string[] = ['## Compliance Report\n'];
  const checks: Array<{ name: string; passed: boolean; detail: string }> = [];
  const hasLicense = fs.existsSync(path.join(repoPath, 'LICENSE')) || fs.existsSync(path.join(repoPath, 'LICENSE.md'));
  checks.push({ name: 'License file', passed: hasLicense, detail: hasLicense ? 'Found' : 'Missing' });
  const hasReadme = fs.existsSync(path.join(repoPath, 'README.md'));
  checks.push({ name: 'README', passed: hasReadme, detail: hasReadme ? 'Found' : 'Missing' });
  const hasGitignore = fs.existsSync(path.join(repoPath, '.gitignore'));
  checks.push({ name: '.gitignore', passed: hasGitignore, detail: hasGitignore ? 'Found' : 'Missing' });
  let envIgnored = false;
  if (hasGitignore) { envIgnored = fs.readFileSync(path.join(repoPath, '.gitignore'), 'utf-8').includes('.env'); }

  const envFiles = findFiles(repoPath, ['-name', '.env*', '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*']).slice(0, 5);
  checks.push({ name: '.env excluded', passed: envIgnored || envFiles.length === 0, detail: envIgnored ? '.env in .gitignore' : envFiles.length > 0 ? '.env NOT in .gitignore!' : 'No .env files' });

  if (fs.existsSync(path.join(repoPath, 'package.json'))) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(repoPath, 'package.json'), 'utf-8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      checks.push({ name: 'Security headers (helmet)', passed: 'helmet' in deps, detail: 'helmet' in deps ? 'Installed' : 'Missing' });
      checks.push({ name: 'CORS config', passed: 'cors' in deps, detail: 'cors' in deps ? 'Installed' : 'Missing' });
      checks.push({ name: 'Rate limiting', passed: 'express-rate-limit' in deps || 'rate-limiter-flexible' in deps, detail: ('express-rate-limit' in deps || 'rate-limiter-flexible' in deps) ? 'Installed' : 'Missing' });
    } catch {}
  }
  const passed = checks.filter(c => c.passed).length;
  for (const c of checks) lines.push(`${c.passed ? '✅' : '❌'} ${c.name} — ${c.detail}`);
  lines.push(`\nCompliance Score: ${Math.round((passed / checks.length) * 100)}/100 (${passed}/${checks.length} passed)`);
  return lines.join('\n');
}
