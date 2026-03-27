import fs from "fs";
import path from "path";
import handlebars from "handlebars";
import puppeteer from "puppeteer";
import { CodeHealthReport } from "./types";
import { ExecutiveSummary } from "./types";

/**
 * Generate PDF report from CodeHealthReport JSON
 */
export async function generatePDFReport(report: CodeHealthReport): Promise<Buffer> {
  console.log(`[Reporter] Generating PDF for ${report.meta.repoName}`);
  
  // Load and compile template
  const templatePath = path.join(__dirname, "templates", "report.html");
  const templateSource = fs.readFileSync(templatePath, "utf8");
  const template = handlebars.compile(templateSource);

  // Prepare template data
  const templateData = {
    ...report,
    // Executive summary data
    executive: report.executive,
    hasExecutive: !!report.executive,
    // Add computed properties for the template
    scanDuration: `${(report.meta.scanDurationMs / 1000).toFixed(1)}s`,
    formattedDate: new Date(report.meta.scanDate).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long", 
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    }),
    scoreColor: getScoreColor(report.summary.overallScore),
    riskColor: getRiskColor(report.summary.riskLevel),
    isDemo: report.meta.version.includes('demo'),
    sections: {
      project: processSection(report.sections.project.raw, "Project Analysis"),
      security: processSection(report.sections.security.raw, "Security Scan"),
      dependencies: processSection(report.sections.dependencies.raw, "Dependency Audit"),
      quality: processSection(report.sections.quality.raw, "Code Quality"),
      coverage: processSection(report.sections.coverage.raw, "Test Coverage"),
      compliance: processSection(report.sections.compliance.raw, "Compliance Check")
    }
  };

  // Render HTML
  const html = template(templateData);

  // Convert to PDF
  const browser = await puppeteer.launch({ 
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });
  const page = await browser.newPage();
  
  await page.setContent(html, { waitUntil: "networkidle0" });
  
  const pdfBuffer = await page.pdf({
    format: "A4",
    printBackground: true,
    margin: {
      top: "20px",
      right: "20px", 
      bottom: "20px",
      left: "20px"
    }
  });

  await browser.close();
  
  console.log(`[Reporter] PDF generated: ${pdfBuffer.length} bytes`);
  return pdfBuffer;
}

/**
 * Get color for score display
 */
function getScoreColor(score: number): string {
  if (score >= 90) return "#10b981"; // green
  if (score >= 75) return "#f59e0b"; // amber
  if (score >= 60) return "#f97316"; // orange
  return "#ef4444"; // red
}

/**
 * Get color for risk level
 */
function getRiskColor(risk: string): string {
  switch (risk) {
    case "low": return "#10b981";
    case "medium": return "#f59e0b";
    case "high": return "#f97316";
    case "critical": return "#ef4444";
    default: return "#6b7280";
  }
}

/**
 * Process raw section output into structured data
 */
function processSection(raw: string, title: string) {
  // Extract key findings, issues, and recommendations
  const lines = raw.split('\n').filter(line => line.trim());
  
  const findings: string[] = [];
  const issues: string[] = [];
  const recommendations: string[] = [];
  
  lines.forEach(line => {
    const lower = line.toLowerCase();
    if (lower.includes('error') || lower.includes('vulnerability') || lower.includes('issue')) {
      issues.push(line.trim());
    } else if (lower.includes('recommend') || lower.includes('fix') || lower.includes('improve')) {
      recommendations.push(line.trim());
    } else if (line.trim().length > 20) { // General findings
      findings.push(line.trim());
    }
  });

  return {
    title,
    raw,
    findings: findings.slice(0, 10), // Limit for readability
    issues: issues.slice(0, 10),
    recommendations: recommendations.slice(0, 10),
    hasContent: findings.length > 0 || issues.length > 0 || recommendations.length > 0
  };
}

/**
 * Register Handlebars helpers
 */
handlebars.registerHelper('eq', (a: any, b: any) => a === b);
handlebars.registerHelper('gt', (a: number, b: number) => a > b);
handlebars.registerHelper('gte', (a: number, b: number) => a >= b);
handlebars.registerHelper('capitalize', (str: string) => str.charAt(0).toUpperCase() + str.slice(1));
handlebars.registerHelper('truncate', (str: string, length: number) => 
  str.length > length ? str.substring(0, length) + '...' : str
);
handlebars.registerHelper('severityColor', (severity: string) => {
  switch (severity) {
    case 'critical': return '#dc2626';
    case 'high': return '#ea580c';
    case 'medium': return '#d97706';
    case 'low': return '#2563eb';
    case 'info': return '#6b7280';
    default: return '#6b7280';
  }
});
handlebars.registerHelper('complexityColor', (complexity: string) => {
  switch (complexity) {
    case 'High': return '#dc2626';
    case 'Medium': return '#d97706';
    case 'Low': return '#16a34a';
    default: return '#6b7280';
  }
});