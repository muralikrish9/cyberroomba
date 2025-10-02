#!/usr/bin/env ts-node
import { withDb } from '../lib/db.js';
import { notificationService } from '../lib/notifications.js';
import { reportService } from '../lib/reports.js';
import type { Db } from 'mongodb';

interface VulnerabilityWithTarget {
  _id: any;
  title: string;
  severity: string;
  confidence: string;
  category?: string;
  description?: string;
  evidence?: Record<string, unknown>;
  cves?: Array<{ id: string; cvss?: { baseScore: number } }>;
  remediation?: string;
  status: string;
  source: string;
  createdAt: string;
  reconId: any;
}

interface ReconWithTarget {
  _id: any;
  subdomain?: string;
  ip?: string;
  targetId: any;
  isAlive: boolean;
  lastChecked: string;
}

interface TargetDoc {
  _id: any;
  program: string;
  asset: { type: string; value: string };
  status: string;
}

async function getHighSeverityVulnerabilities(db: Db): Promise<VulnerabilityWithTarget[]> {
  const results = await db.collection('vulnerabilities').aggregate([
    {
      $match: {
        severity: { $in: ['critical', 'high'] },
        status: 'open',
      },
    },
    {
      $addFields: {
        reconObjectId: { $toObjectId: '$reconId' }
      }
    },
    {
      $lookup: {
        from: 'recon_results',
        localField: 'reconObjectId',
        foreignField: '_id',
        as: 'recon',
      },
    },
    {
      $addFields: {
        targetObjectId: { $toObjectId: { $arrayElemAt: ['$recon.targetId', 0] } }
      }
    },
    {
      $lookup: {
        from: 'targets',
        localField: 'targetObjectId',
        foreignField: '_id',
        as: 'target',
      },
    },
    {
      $match: {
        'recon.isAlive': true,
        'target.status': 'active',
      },
    },
  ]).toArray();
  
  return results as VulnerabilityWithTarget[];
}

async function generateReportsForVulnerabilities(db: Db, vulnerabilities: VulnerabilityWithTarget[]): Promise<void> {
  const reportsDir = 'data/reports';
  
  for (const vuln of vulnerabilities) {
    try {
      // Get the associated recon and target data
      const recon = await db.collection('recon_results').findOne({ _id: vuln.reconId });
      const target = await db.collection('targets').findOne({ _id: recon?.targetId });

      if (!recon || !target) {
        console.warn(`[reports] Missing recon or target data for vulnerability ${vuln._id}`);
        continue;
      }

      const reconHost = recon.subdomain || recon.ip || 'unknown';
      const program = target.program.replace(/^(bugcrowd|hackerone|intigriti):/, '');

      // Generate report
      const reportData = {
        vulnerability: vuln as any,
        target: target as any,
        reconHost,
        program,
      };

      const report = await reportService.generateReport(reportData);
      
      // Save report to file
      const filepath = await reportService.saveReportToFile(report, reportsDir);
      console.log(`[reports] Generated report: ${filepath}`);

      // Store report in database
      await db.collection('reports').insertOne({
        ...report,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: [],
      });

      // Send Discord notification for all severity levels (routed to appropriate channels)
      await notificationService.notifyVulnerabilityFinding(vuln as any, reconHost);
      console.log(`[reports] Sent Discord notification for ${vuln.severity} finding: ${vuln.title}`);

    } catch (error) {
      console.error(`[reports] Failed to process vulnerability ${vuln._id}:`, (error as Error).message);
    }
  }
}

async function generateDailySummary(db: Db): Promise<void> {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayISO = today.toISOString();

  const summary = await db.collection('vulnerabilities').aggregate([
    {
      $facet: {
        total: [{ $count: 'count' }],
        bySeverity: [
          { $group: { _id: '$severity', count: { $sum: 1 } } }
        ],
        newToday: [
          { $match: { createdAt: { $gte: todayISO } } },
          { $count: 'count' }
        ]
      }
    }
  ]).toArray();

  const totalTargets = await db.collection('targets').countDocuments();
  const totalHosts = await db.collection('recon_results').countDocuments();
  const totalVulns = summary[0]?.total?.[0]?.count || 0;
  const newToday = summary[0]?.newToday?.[0]?.count || 0;

  const severityCounts = (summary[0]?.bySeverity || []).reduce((acc: any, item: any) => {
    acc[item._id] = item.count;
    return acc;
  }, {});

  const dailySummary = {
    totalTargets,
    totalHosts,
    totalVulnerabilities: totalVulns,
    criticalCount: severityCounts.critical || 0,
    highCount: severityCounts.high || 0,
    newFindings: newToday,
  };

  await notificationService.notifyDailySummary(dailySummary);
  console.log('[reports] Sent daily summary notification');
}

async function main(): Promise<void> {
  await withDb(async (db) => {
    console.log('[reports] Starting report generation and notifications...');

    // Get high severity vulnerabilities
    const highSeverityVulns = await getHighSeverityVulnerabilities(db);
    console.log(`[reports] Found ${highSeverityVulns.length} high-severity vulnerabilities`);

    if (highSeverityVulns.length > 0) {
      // Generate reports and send notifications
      await generateReportsForVulnerabilities(db, highSeverityVulns);
    }

    // Generate daily summary
    await generateDailySummary(db);

    console.log('[reports] Report generation completed');
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exitCode = 1;
}).finally(() => {
  // Close database connection
  import('../lib/db.js').then(({ closeDatabase }) => {
    closeDatabase().then(() => {
      console.log('[reports] Database connection closed');
      process.exit(process.exitCode || 0);
    });
  });
});
