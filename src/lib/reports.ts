import type { Vulnerability, Report, Target } from '../schemas/index.js';
import { randomUUID } from 'node:crypto';

export interface ReportTemplate {
  title: string;
  executiveSummary: string;
  technicalDetails: string;
  remediation: string;
  references: string[];
}

export interface ReportData {
  vulnerability: Vulnerability;
  target: Target;
  reconHost: string;
  program: string;
}

class ReportService {
  private generateReportId(): string {
    return `CR-${Date.now()}-${randomUUID().slice(0, 8).toUpperCase()}`;
  }

  private getSeverityEmoji(severity: string): string {
    const emojis = {
      critical: '🚨',
      high: '⚠️',
      medium: '🔶',
      low: '🔸',
      info: 'ℹ️',
    };
    return emojis[severity as keyof typeof emojis] || '🔸';
  }

  private formatCVEList(cves: Vulnerability['cves']): string {
    if (!cves || cves.length === 0) return 'None identified';
    
    return cves.map(cve => {
      const cvss = cve.cvss?.baseScore ? ` (CVSS: ${cve.cvss.baseScore})` : '';
      return `- ${cve.id}${cvss}`;
    }).join('\n');
  }

  private generateMarkdownReport(data: ReportData): string {
    const { vulnerability, target, reconHost, program } = data;
    const emoji = this.getSeverityEmoji(vulnerability.severity);
    const reportId = this.generateReportId();

    return `# ${emoji} ${vulnerability.title}

**Report ID:** \`${reportId}\`  
**Severity:** ${vulnerability.severity.toUpperCase()}  
**Confidence:** ${vulnerability.confidence}  
**Program:** ${program}  
**Target:** \`${reconHost}\`  
**Discovered:** ${new Date(vulnerability.createdAt).toLocaleDateString()}  

---

## Executive Summary

${vulnerability.description || 'No description provided'}

This vulnerability affects the target \`${reconHost}\` and has been classified as **${vulnerability.severity.toUpperCase()}** severity with **${vulnerability.confidence}** confidence.

---

## Technical Details

### Vulnerability Information
- **Category:** ${vulnerability.category || 'Not specified'}
- **Source:** ${vulnerability.source}
- **Status:** ${vulnerability.status}

### Affected Systems
- **Primary Target:** \`${target.asset.value}\`
- **Discovered Host:** \`${reconHost}\`
- **Asset Type:** ${target.asset.type}

### Evidence
\`\`\`json
${JSON.stringify(vulnerability.evidence, null, 2)}
\`\`\`

### CVEs
${this.formatCVEList(vulnerability.cves)}

---

## Remediation

${vulnerability.remediation || 'No specific remediation guidance provided. Please consult the security team for appropriate mitigation steps.'}

### Recommended Actions
1. **Immediate:** Review and validate the finding
2. **Short-term:** Implement appropriate security controls
3. **Long-term:** Establish monitoring and detection capabilities

---

## References

${vulnerability.cves?.map(cve => `- [CVE-${cve.id}](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id})`).join('\n') || '- No additional references available'}

---

*This report was generated automatically by CyberRoomba on ${new Date().toISOString()}*
`;
  }

  private generateHTMLReport(data: ReportData): string {
    const { vulnerability, target, reconHost, program } = data;
    const emoji = this.getSeverityEmoji(vulnerability.severity);
    const reportId = this.generateReportId();
    const markdown = this.generateMarkdownReport(data);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${vulnerability.title} - CyberRoomba Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        .header { border-bottom: 2px solid #e1e5e9; padding-bottom: 20px; margin-bottom: 30px; }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .severity-info { color: #17a2b8; }
        .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #28a745; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${emoji} ${vulnerability.title}</h1>
        <p><strong>Report ID:</strong> <code>${reportId}</code></p>
        <p><strong>Severity:</strong> <span class="badge badge-${vulnerability.severity}">${vulnerability.severity.toUpperCase()}</span></p>
        <p><strong>Program:</strong> ${program}</p>
        <p><strong>Target:</strong> <code>${reconHost}</code></p>
        <p><strong>Discovered:</strong> ${new Date(vulnerability.createdAt).toLocaleDateString()}</p>
    </div>

    <h2>Executive Summary</h2>
    <p>${vulnerability.description || 'No description provided'}</p>

    <h2>Technical Details</h2>
    <h3>Vulnerability Information</h3>
    <ul>
        <li><strong>Category:</strong> ${vulnerability.category || 'Not specified'}</li>
        <li><strong>Source:</strong> ${vulnerability.source}</li>
        <li><strong>Status:</strong> ${vulnerability.status}</li>
        <li><strong>Confidence:</strong> ${vulnerability.confidence}</li>
    </ul>

    <h3>Affected Systems</h3>
    <ul>
        <li><strong>Primary Target:</strong> <code>${target.asset.value}</code></li>
        <li><strong>Discovered Host:</strong> <code>${reconHost}</code></li>
        <li><strong>Asset Type:</strong> ${target.asset.type}</li>
    </ul>

    <h3>Evidence</h3>
    <pre>${JSON.stringify(vulnerability.evidence, null, 2)}</pre>

    <h3>CVEs</h3>
    <ul>
        ${vulnerability.cves?.map(cve => 
          `<li><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}">${cve.id}</a>${cve.cvss?.baseScore ? ` (CVSS: ${cve.cvss.baseScore})` : ''}</li>`
        ).join('') || '<li>None identified</li>'}
    </ul>

    <h2>Remediation</h2>
    <p>${vulnerability.remediation || 'No specific remediation guidance provided. Please consult the security team for appropriate mitigation steps.'}</p>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e1e5e9; color: #6c757d; font-size: 0.9em;">
        <p>This report was generated automatically by CyberRoomba on ${new Date().toISOString()}</p>
    </footer>
</body>
</html>`;
  }

  async generateReport(data: ReportData): Promise<Report> {
    const reportId = this.generateReportId();
    const markdown = this.generateMarkdownReport(data);
    const html = this.generateHTMLReport(data);

    const report: Omit<Report, '_id' | 'createdAt' | 'updatedAt' | 'tags'> = {
      program: data.program,
      vulnIds: [data.vulnerability._id as any],
      reportId,
      status: 'draft',
      content: {
        title: data.vulnerability.title,
        body: markdown,
      },
    };

    return report as Report;
  }

  async saveReportToFile(report: Report, outputDir: string): Promise<string> {
    const { writeFile, ensureDir } = await import('./files.js');
    const { join } = await import('node:path');

    await ensureDir(outputDir);

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `report-${timestamp}-${report.reportId}.md`;
    const filepath = join(outputDir, filename);

    await writeFile(filepath, report.content.body);

    return filepath;
  }
}

export const reportService = new ReportService();
