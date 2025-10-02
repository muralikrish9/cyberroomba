#!/usr/bin/env ts-node
import { writeJsonFile, ensureDir } from '../lib/files.js';
import { config } from '../lib/config.js';
import { withDb } from '../lib/db.js';
import { startJob, finishJob } from '../lib/jobRuns.js';
import { notificationService } from '../lib/notifications.js';
import type { Db } from 'mongodb';
import { ObjectId } from 'mongodb';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { cpus, totalmem } from 'node:os';

interface AttackResult {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'suspected' | 'needs-review';
  description: string;
  evidence: Record<string, any>;
  source: string;
  reconId: string;
  jobId: string;
}

// Nuclei Attack Templates
async function performNucleiAttacks(target: string, outputDir: string, reconId: string, jobId: string): Promise<AttackResult[]> {
  return new Promise((resolve) => {
    console.log(`      ⚔️ Running Nuclei attack templates on: ${target}`);
    
    const nuclei = spawn('nuclei', [
      '-u', target,
      '-t', 'nuclei-templates/',
      '-severity', 'critical,high,medium,low',
      '-silent',
      '-json',
      '-timeout', '60',
      '-rate-limit', '100',
      '-bulk-size', '50',
      '-retries', '2'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const attacks: AttackResult[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          
          // Map Nuclei severity to our system
          let severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
          switch (result.info?.severity?.toLowerCase()) {
            case 'critical': severity = 'critical'; break;
            case 'high': severity = 'high'; break;
            case 'medium': severity = 'medium'; break;
            case 'low': severity = 'low'; break;
            default: severity = 'info';
          }

          // Map Nuclei confidence to our system
          let confidence: 'confirmed' | 'suspected' | 'needs-review' = 'suspected';
          if (result.info?.classification?.cvss_score >= 7) {
            confidence = 'confirmed';
          } else if (result.info?.classification?.cvss_score >= 4) {
            confidence = 'suspected';
          }

          attacks.push({
            title: result.info?.name || 'Nuclei Attack Template',
            severity,
            confidence,
            description: result.info?.description || `Attack template executed on ${target}`,
            evidence: {
              nuclei_result: result,
              target: target,
              timestamp: new Date().toISOString(),
              template_id: result.template_id,
              template_path: result.template_path,
              matched_at: result.matched_at,
              curl_command: result.curl_command,
              request: result.request,
              response: result.response,
              extracted_results: result.extracted_results
            },
            source: 'nuclei-attack',
            reconId,
            jobId
          });

          process.stdout.write(`      🚨 [${severity.toUpperCase()}] ${result.info?.name} - ${result.matched_at}\n`);
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
      writeFileSync(join(outputDir, `nuclei-attacks-${reconId}.json`), output);
      console.log(`      📁 Nuclei attack output saved to: nuclei-attacks-${reconId}.json`);
      resolve(attacks);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei error: ${error.message}`);
      console.log(`      💡 Make sure nuclei is installed and nuclei-templates directory exists`);
      resolve([]);
    });
  });
}

// Nuclei XSS Attack Templates
async function performNucleiXssAttacks(target: string, outputDir: string, reconId: string, jobId: string): Promise<AttackResult[]> {
  return new Promise((resolve) => {
    console.log(`      🎯 Running Nuclei XSS attack templates on: ${target}`);
    
    const nuclei = spawn('nuclei', [
      '-u', target,
      '-t', 'nuclei-templates/exposures/',
      '-t', 'nuclei-templates/vulnerabilities/',
      '-tags', 'xss,reflected-xss,stored-xss',
      '-severity', 'critical,high,medium',
      '-silent',
      '-json'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const attacks: AttackResult[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          attacks.push({
            title: result.info?.name || 'XSS Vulnerability',
            severity: 'high',
            confidence: 'confirmed',
            description: `XSS attack template executed: ${result.info?.description}`,
            evidence: {
              nuclei_result: result,
              target: target,
              timestamp: new Date().toISOString(),
              attack_type: 'xss',
              payload: result.request?.body || result.request?.path
            },
            source: 'nuclei-xss',
            reconId,
            jobId
          });
          process.stdout.write(`      🎯 XSS: ${result.info?.name} - ${result.matched_at}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    nuclei.on('close', (code) => {
      writeFileSync(join(outputDir, `nuclei-xss-${reconId}.json`), output);
      console.log(`      📁 Nuclei XSS output saved to: nuclei-xss-${reconId}.json`);
      resolve(attacks);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei XSS error: ${error.message}`);
      resolve([]);
    });
  });
}

// Nuclei Directory/Path Discovery Templates
async function performNucleiPathDiscovery(target: string, outputDir: string, reconId: string, jobId: string): Promise<AttackResult[]> {
  return new Promise((resolve) => {
    console.log(`      🔍 Running Nuclei path discovery templates on: ${target}`);
    
    const nuclei = spawn('nuclei', [
      '-u', target,
      '-t', 'nuclei-templates/exposures/',
      '-t', 'nuclei-templates/misconfiguration/',
      '-tags', 'exposed-panel,admin-panel,backup,config,debug',
      '-severity', 'critical,high,medium',
      '-silent',
      '-json'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const attacks: AttackResult[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          attacks.push({
            title: result.info?.name || 'Exposed Path/File',
            severity: 'medium',
            confidence: 'confirmed',
            description: `Exposed path or sensitive file discovered: ${result.info?.description}`,
            evidence: {
              nuclei_result: result,
              target: target,
              timestamp: new Date().toISOString(),
              exposed_path: result.matched_at,
              response_code: result.response?.status_code
            },
            source: 'nuclei-path-discovery',
            reconId,
            jobId
          });
          process.stdout.write(`      🔍 Exposed: ${result.info?.name} - ${result.matched_at}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    nuclei.on('close', (code) => {
      writeFileSync(join(outputDir, `nuclei-paths-${reconId}.json`), output);
      console.log(`      📁 Nuclei path discovery output saved to: nuclei-paths-${reconId}.json`);
      resolve(attacks);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei path discovery error: ${error.message}`);
      resolve([]);
    });
  });
}

// Nuclei Authentication Bypass Templates
async function performNucleiAuthBypass(target: string, outputDir: string, reconId: string, jobId: string): Promise<AttackResult[]> {
  return new Promise((resolve) => {
    console.log(`      🔓 Running Nuclei authentication bypass templates on: ${target}`);
    
    const nuclei = spawn('nuclei', [
      '-u', target,
      '-t', 'nuclei-templates/vulnerabilities/',
      '-t', 'nuclei-templates/exposures/',
      '-tags', 'auth-bypass,default-login,weak-auth,no-auth',
      '-severity', 'critical,high,medium',
      '-silent',
      '-json'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const attacks: AttackResult[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          attacks.push({
            title: result.info?.name || 'Authentication Bypass',
            severity: 'critical',
            confidence: 'confirmed',
            description: `Authentication bypass discovered: ${result.info?.description}`,
            evidence: {
              nuclei_result: result,
              target: target,
              timestamp: new Date().toISOString(),
              auth_bypass_type: result.info?.tags?.join(', '),
              credentials_tested: result.request?.body || result.request?.path
            },
            source: 'nuclei-auth-bypass',
            reconId,
            jobId
          });
          process.stdout.write(`      🔓 Auth Bypass: ${result.info?.name} - ${result.matched_at}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    nuclei.on('close', (code) => {
      writeFileSync(join(outputDir, `nuclei-auth-${reconId}.json`), output);
      console.log(`      📁 Nuclei auth bypass output saved to: nuclei-auth-${reconId}.json`);
      resolve(attacks);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei auth bypass error: ${error.message}`);
      resolve([]);
    });
  });
}

// Nuclei SSRF & XXE Attack Templates
async function performNucleiSSRFAttacks(target: string, outputDir: string, reconId: string, jobId: string): Promise<AttackResult[]> {
  return new Promise((resolve) => {
    console.log(`      🌐 Running Nuclei SSRF & XXE attack templates on: ${target}`);
    
    const nuclei = spawn('nuclei', [
      '-u', target,
      '-t', 'nuclei-templates/vulnerabilities/',
      '-tags', 'ssrf,xxe,server-side-request-forgery,xml-external-entity',
      '-severity', 'critical,high,medium',
      '-silent',
      '-json'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const attacks: AttackResult[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          attacks.push({
            title: result.info?.name || 'SSRF/XXE Vulnerability',
            severity: 'high',
            confidence: 'confirmed',
            description: `SSRF or XXE attack template executed: ${result.info?.description}`,
            evidence: {
              nuclei_result: result,
              target: target,
              timestamp: new Date().toISOString(),
              attack_type: 'ssrf-xxe',
              payload: result.request?.body || result.request?.path
            },
            source: 'nuclei-ssrf-xxe',
            reconId,
            jobId
          });
          process.stdout.write(`      🌐 SSRF/XXE: ${result.info?.name} - ${result.matched_at}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    nuclei.on('close', (code) => {
      writeFileSync(join(outputDir, `nuclei-ssrf-xxe-${reconId}.json`), output);
      console.log(`      📁 Nuclei SSRF/XXE output saved to: nuclei-ssrf-xxe-${reconId}.json`);
      resolve(attacks);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei SSRF/XXE error: ${error.message}`);
      resolve([]);
    });
  });
}

// Nuclei Injection Attack Templates
async function performNucleiInjectionAttacks(target: string, outputDir: string, reconId: string, jobId: string): Promise<AttackResult[]> {
  return new Promise((resolve) => {
    console.log(`      📁 Running Nuclei injection attack templates on: ${target}`);
    
    const nuclei = spawn('nuclei', [
      '-u', target,
      '-t', 'nuclei-templates/vulnerabilities/',
      '-tags', 'injection,command-injection,file-inclusion,ldap-injection,no-sql-injection',
      '-severity', 'critical,high,medium',
      '-silent',
      '-json'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const attacks: AttackResult[] = [];

    nuclei.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          attacks.push({
            title: result.info?.name || 'Injection Vulnerability',
            severity: 'critical',
            confidence: 'confirmed',
            description: `Injection attack template executed: ${result.info?.description}`,
            evidence: {
              nuclei_result: result,
              target: target,
              timestamp: new Date().toISOString(),
              attack_type: 'injection',
              payload: result.request?.body || result.request?.path
            },
            source: 'nuclei-injection',
            reconId,
            jobId
          });
          process.stdout.write(`      📁 Injection: ${result.info?.name} - ${result.matched_at}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    nuclei.on('close', (code) => {
      writeFileSync(join(outputDir, `nuclei-injection-${reconId}.json`), output);
      console.log(`      📁 Nuclei injection output saved to: nuclei-injection-${reconId}.json`);
      resolve(attacks);
    });

    nuclei.on('error', (error) => {
      console.error(`      ❌ Nuclei injection error: ${error.message}`);
      resolve([]);
    });
  });
}

// Main attack function
async function runAttackJob(db: Db, jobId: string, reconId: string) {
  const rawDir = join(config.vulnRawDir, jobId);
  await ensureDir(rawDir);

  // Get recon and target information
  const recon = await db.collection('recon_results').findOne({ _id: new ObjectId(reconId) });
  const target = recon ? await db.collection('targets').findOne({ _id: new ObjectId(recon.targetId) }) : null;
  
  if (!target || !target.program || (!target.program.startsWith('bugcrowd:') && !target.program.startsWith('hackerone:') && !target.program.startsWith('intigriti:'))) {
    console.log(`[attacks] Skipping non-bug-bounty target: ${target?.asset?.value || 'unknown'}`);
    return 0;
  }

  const reconHost = recon?.subdomain || recon?.ip || 'unknown';
  const targetUrl = `http://${reconHost}`;
  
  console.log(`\n⚔️ [attacks] Starting attack phase on: ${reconHost}`);
  console.log(`   Target: ${target.asset.value} (${target.program})`);
  console.log(`   Attack URL: ${targetUrl}`);

  let totalAttacks = 0;
  const allAttacks: AttackResult[] = [];

  try {
    // Run all attack phases in parallel for speed
    console.log(`   🚀 Running all 6 attack phases in parallel...`);
    
    const [
      generalAttacks,
      xssAttacks, 
      pathAttacks,
      authAttacks,
      ssrfAttacks,
      injectionAttacks
    ] = await Promise.all([
      performNucleiAttacks(targetUrl, rawDir, reconId, jobId),
      performNucleiXssAttacks(targetUrl, rawDir, reconId, jobId),
      performNucleiPathDiscovery(targetUrl, rawDir, reconId, jobId),
      performNucleiAuthBypass(targetUrl, rawDir, reconId, jobId),
      performNucleiSSRFAttacks(targetUrl, rawDir, reconId, jobId),
      performNucleiInjectionAttacks(targetUrl, rawDir, reconId, jobId)
    ]);

    allAttacks.push(...generalAttacks, ...xssAttacks, ...pathAttacks, ...authAttacks, ...ssrfAttacks, ...injectionAttacks);
    totalAttacks = allAttacks.length;

    // Store successful attacks in database
    if (allAttacks.length > 0) {
      const enrichedAttacks = allAttacks.map(attack => ({
        ...attack,
        cves: [], // Add empty CVE array for compatibility
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: 'open' as const,
        tags: ['attack-phase']
      }));

      await db.collection('vulnerabilities').insertMany(enrichedAttacks);
      console.log(`   🎯 Stored ${enrichedAttacks.length} successful attacks in database`);

      // Send Discord notifications for each successful attack
      for (const attack of enrichedAttacks) {
        try {
          await notificationService.notifyVulnerabilityFinding(attack, reconHost);
          console.log(`   📢 Sent Discord notification for ${attack.severity} attack: ${attack.title}`);
        } catch (error) {
          console.error(`   ❌ Failed to send notification: ${(error as Error).message}`);
        }
      }
    }

  } catch (error) {
    console.error(`   ❌ Error during attack phase: ${(error as Error).message}`);
  }

  console.log(`   ✅ Attack phase complete for ${reconHost} - ${totalAttacks} successful attacks\n`);
  return totalAttacks;
}

// Parallel attack processing with worker pool
async function runParallelAttacks(db: Db, jobId: string, reconDocs: any[], maxConcurrent: number = 20) {
  const results: number[] = [];
  let completed = 0;
  let successful = 0;
  
  console.log(`\n🚀 Starting PARALLEL attack phase on ${reconDocs.length} hosts with ${maxConcurrent} workers...\n`);
  
  // Create worker pool
  const workers: Promise<number>[] = [];
  let currentIndex = 0;
  
  // Start initial batch of workers with staggered delays
  for (let i = 0; i < Math.min(maxConcurrent, reconDocs.length); i++) {
    const recon = reconDocs[currentIndex++];
    
    // Add small delay to prevent overwhelming the system
    const delay = i * 100; // 100ms stagger between workers
    
    workers.push(
      new Promise(resolve => setTimeout(resolve, delay))
        .then(() => runAttackJob(db, jobId, String(recon._id)))
        .then(result => {
          completed++;
          successful += result;
          console.log(`\n📊 Parallel Progress: ${completed}/${reconDocs.length} hosts completed (${successful} successful attacks)`);
          return result;
        })
        .catch(error => {
          completed++;
          console.error(`\n❌ Attack failed for host: ${error.message}`);
          return 0;
        })
    );
  }
  
  // Process remaining hosts as workers complete
  while (currentIndex < reconDocs.length) {
    // Wait for at least one worker to complete
    const completedWorkerIndex = await Promise.race(
      workers.map((worker, index) => worker.then(() => index).catch(() => index))
    );
    
    // Start new worker for next host
    const recon = reconDocs[currentIndex++];
    workers[completedWorkerIndex] = runAttackJob(db, jobId, String(recon._id))
      .then(result => {
        completed++;
        successful += result;
        console.log(`\n📊 Parallel Progress: ${completed}/${reconDocs.length} hosts completed (${successful} successful attacks)`);
        return result;
      })
      .catch(error => {
        completed++;
        console.error(`\n❌ Attack failed for host: ${error.message}`);
        return 0;
      });
  }
  
  // Wait for all remaining workers to complete
  const finalResults = await Promise.allSettled(workers);
  const totalSuccessful = finalResults.reduce((sum, result) => {
    return sum + (result.status === 'fulfilled' ? result.value : 0);
  }, 0);
  
  return totalSuccessful;
}

async function main(): Promise<void> {
  await withDb(async (db) => {
    const job = await startJob(db, 'attack-drone', 'cli');
    try {
      // Get alive hosts from our selected targets
      const reconDocs = await db
        .collection('recon_results')
        .find({ 
          isAlive: true,
          subdomain: { $exists: true, $ne: null }
        })
        .limit(100) // Increased limit for parallel processing
        .toArray();

      console.log(`\n⚔️ Found ${reconDocs.length} targets for parallel attacks`);
      console.log(`💻 Machine resources: ${cpus().length} CPU cores available`);
      console.log(`🧠 Memory: ${Math.round(totalmem() / 1024 / 1024 / 1024)}GB total`);
      
      // Determine optimal concurrency based on system resources
      const cpuCores = cpus().length;
      const maxConcurrent = Math.min(20, Math.max(5, cpuCores * 2)); // Conservative scaling
      
      console.log(`🎯 Using ${maxConcurrent} parallel workers (conservative for stability)`);
      
      const total = await runParallelAttacks(db, job.jobId, reconDocs, maxConcurrent);

      await finishJob(db, job, 'success', { hostsAttacked: reconDocs.length, successfulAttacks: total });
      console.log(`\n🎉 [attacks] PARALLEL attack complete! ${reconDocs.length} hosts attacked, ${total} successful attacks found`);
    } catch (error) {
      await finishJob(db, job, 'failed', undefined, error as Error);
      throw error;
    }
  });
}

main().catch((error) => {
  console.error('Fatal error caught:', error);
  console.error('Error type:', typeof error);
  console.error('Error message:', error?.message);
  console.error('Error stack:', error?.stack);
  process.exitCode = 1;
}).finally(() => {
  import('../lib/db.js').then(({ closeDatabase }) => {
    closeDatabase().then(() => {
      console.log('[attacks] Database connection closed');
      process.exit(process.exitCode || 0);
    });
  });
});
