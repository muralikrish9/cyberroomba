import { writeJsonFile, ensureDir } from '../lib/files.js';
import { config } from '../lib/config.js';
import { withDb } from '../lib/db.js';
import { startJob, finishJob } from '../lib/jobRuns.js';
import { parseNucleiResults, parseNmapVulnerabilities, mergeFindings } from '../vuln/parse.js';
import { CveMatcher } from '../vuln/matcher.js';
import { notificationService } from '../lib/notifications.js';
import type { Db } from 'mongodb';
import { ObjectId } from 'mongodb';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Real vulnerability scanning tool implementations

import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';

async function runNuclei(target: string, outputDir: string, reconId: string): Promise<any[]> {
  return new Promise((resolve) => {
    console.log(`      🔍 Running: nuclei -u ${target} -silent -json`);
    
    const nuclei = spawn('nuclei', ['-u', target, '-silent', '-json'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const vulnerabilities: any[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          vulnerabilities.push(result);
          process.stdout.write(`      🚨 [${result.info.severity?.toUpperCase() || 'INFO'}] ${result.info.name} - ${result.matched_at}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    nuclei.stderr.on('data', (data) => {
      console.error(`      ⚠️  Nuclei warning: ${data.toString()}`);
    });

    nuclei.on('close', (code) => {
      writeFileSync(join(outputDir, `nuclei-${reconId}.json`), output);
      console.log(`      📁 Nuclei output saved to: nuclei-${reconId}.json`);
      resolve(vulnerabilities);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei error: ${error.message}`);
      console.log(`      💡 Make sure nuclei is installed and in PATH`);
      resolve([]);
    });
  });
}

async function runNmap(target: string, outputDir: string, reconId: string): Promise<any[]> {
  return new Promise((resolve) => {
    console.log(`      🔍 Running: nmap -sV -sC --script vuln ${target}`);
    
    const nmap = spawn('nmap', ['-sV', '-sC', '--script', 'vuln', target], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const vulnerabilities: any[] = [];

    nmap.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      process.stdout.write(`      ${text}`);
      
      // Parse nmap output for vulnerabilities
      if (text.includes('VULNERABLE') || text.includes('CVE-')) {
        vulnerabilities.push({
          title: 'Nmap Vulnerability Scan',
          description: text.trim(),
          severity: 'medium',
          confidence: 'suspected',
          source: 'nmap',
          evidence: {
            nmap_output: text.trim(),
            target: target,
            timestamp: new Date().toISOString()
          }
        });
      }
    });

    nmap.stderr.on('data', (data) => {
      console.error(`      ⚠️  Nmap warning: ${data.toString()}`);
    });

    nmap.on('close', (code) => {
      writeFileSync(join(outputDir, `nmap-${reconId}.txt`), output);
      console.log(`      📁 Nmap output saved to: nmap-${reconId}.txt`);
      resolve(vulnerabilities);
    });

    nmap.on('error', (error) => {
      console.error(`      ❌ Nmap error: ${error.message}`);
      console.log(`      💡 Make sure nmap is installed and in PATH`);
      resolve([]);
    });
  });
}

async function runVulnJob(db: Db, jobId: string, reconId: string) {
  const rawDir = join(config.vulnRawDir, jobId);
  await ensureDir(rawDir);

  // Get recon and target information
  const recon = await db.collection('recon_results').findOne({ _id: new ObjectId(reconId) });
  const target = recon ? await db.collection('targets').findOne({ _id: new ObjectId(recon.targetId) }) : null;
  
  if (!target || !target.program || (!target.program.startsWith('bugcrowd:') && !target.program.startsWith('hackerone:') && !target.program.startsWith('intigriti:'))) {
    console.log(`[vuln] Skipping non-bug-bounty target: ${target?.asset?.value || 'unknown'}`);
    return 0;
  }

  const reconHost = recon?.subdomain || recon?.ip || 'unknown';
  console.log(`\n🚨 [vuln] Starting vulnerability scan on: ${reconHost}`);
  console.log(`   Target: ${target.asset.value} (${target.program})`);
  console.log(`   Recon Host: ${reconHost}`);

  let vulnerabilities = 0;

  try {
    // Step 1: Nuclei vulnerability scanning
    console.log(`   🔍 Running Nuclei vulnerability scanner...`);
    const nucleiResults = await runNuclei(reconHost, rawDir, reconId);
    if (nucleiResults.length > 0) {
      console.log(`   ✅ Found ${nucleiResults.length} vulnerabilities with Nuclei`);
      vulnerabilities += nucleiResults.length;
    } else {
      console.log(`   ✅ No vulnerabilities found with Nuclei`);
    }

    // Step 2: Skip Nmap (can get stuck)
    console.log(`   ⏭️  Skipping Nmap (can get stuck), using Nuclei results only`);

    // Store all vulnerabilities in database
    const allFindings = [...nucleiResults];
    if (allFindings.length > 0) {
      const enrichedFindings = allFindings.map(finding => ({
        ...finding,
        reconId: reconId,
        jobId: jobId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: 'open',
        tags: []
      }));

      await db.collection('vulnerabilities').insertMany(enrichedFindings);
      console.log(`   🎯 Stored ${enrichedFindings.length} vulnerabilities in database`);

      // Send Discord notifications for each finding
      for (const finding of enrichedFindings) {
        try {
          await notificationService.notifyVulnerabilityFinding(finding, reconHost);
          console.log(`   📢 Sent Discord notification for ${finding.severity} finding: ${finding.title}`);
        } catch (error) {
          console.error(`   ❌ Failed to send notification: ${(error as Error).message}`);
        }
      }
    }

  } catch (error) {
    console.error(`   ❌ Error during vulnerability scanning: ${(error as Error).message}`);
  }

  console.log(`   ✅ Vulnerability scanning complete for ${reconHost} - Found ${vulnerabilities} vulnerabilities\n`);
  return vulnerabilities;
}

async function main(): Promise<void> {
  await withDb(async (db) => {
    const job = await startJob(db, 'vuln-scanner', 'cli');
    try {
      const reconDocs = await db
        .collection('recon_results')
        .find({ isAlive: true })
        .limit(20) // Scale up vulnerability scanning
        .toArray();

      let total = 0;
      console.log(`\n🚨 Starting vulnerability scanning on ${reconDocs.length} alive hosts...\n`);
      
      for (let i = 0; i < reconDocs.length; i++) {
        const recon = reconDocs[i];
        if (recon) {
          console.log(`\n📊 Progress: ${i + 1}/${reconDocs.length} hosts`);
          total += await runVulnJob(db, job.jobId, String(recon._id));
        }
      }

      await finishJob(db, job, 'success', { hostsScanned: reconDocs.length, findings: total });
      console.log(`[vuln] hosts scanned ${reconDocs.length}, findings inserted ${total}`);
    } catch (error) {
      await finishJob(db, job, 'failed', undefined, error as Error);
      throw error;
    }
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}).finally(() => {
  // Close database connection
  import('../lib/db.js').then(({ closeDatabase }) => {
    closeDatabase().then(() => {
      console.log('[vuln] Database connection closed');
      process.exit(process.exitCode || 0);
    });
  });
});
