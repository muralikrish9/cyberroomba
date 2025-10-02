import { writeJsonFile, ensureDir } from '../lib/files.js';
import { config } from '../lib/config.js';
import { withDb } from '../lib/db.js';
import { startJob, finishJob } from '../lib/jobRuns.js';
import { normalizeRecon } from '../recon/normalize.js';
import type { Db, ObjectId } from 'mongodb';
import { ObjectId as MongoObjectId } from 'mongodb';
import { resolve, join } from 'node:path';
import { readFileSync } from 'node:fs';

interface TargetDoc {
  _id: ObjectId | string;
  program: string;
  asset: { type: string; value: string };
  lastReconAt?: string;
  status: string;
}

function toObjectId(id: ObjectId | string): ObjectId {
  return typeof id === 'string' ? new MongoObjectId(id) : id;
}

// Real reconnaissance tool implementations

import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { cpus, totalmem } from 'node:os';

async function runSubfinder(domain: string, outputDir: string, safeName: string): Promise<string[]> {
  return new Promise((resolve) => {
    console.log(`      🔍 Running: subfinder -d ${domain} -silent`);
    
    const subfinder = spawn('subfinder', ['-d', domain, '-silent'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const subdomains: string[] = [];

    subfinder.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      subdomains.push(...lines);
      output += data.toString();
      process.stdout.write(`      ${data.toString()}`);
    });

    subfinder.stderr.on('data', (data) => {
      console.error(`      ⚠️  Subfinder warning: ${data.toString()}`);
    });

    subfinder.on('close', (code) => {
      // Save raw output
      writeFileSync(join(outputDir, `subfinder-${safeName}.txt`), output);
      console.log(`      📁 Subfinder output saved to: subfinder-${safeName}.txt`);
      resolve(subdomains);
    });

    subfinder.on('error', (error) => {
      console.error(`      ❌ Subfinder error: ${error.message}`);
      console.log(`      💡 Make sure subfinder is installed and in PATH`);
      resolve([]);
    });
  });
}

async function runAmass(domain: string, outputDir: string, safeName: string): Promise<string[]> {
  return new Promise((resolve) => {
    console.log(`      🔍 Running: amass enum -d ${domain} -silent`);
    
    const amass = spawn('amass', ['enum', '-d', domain, '-silent'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const subdomains: string[] = [];

    amass.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      subdomains.push(...lines);
      output += data.toString();
      process.stdout.write(`      ${data.toString()}`);
    });

    amass.stderr.on('data', (data) => {
      console.error(`      ⚠️  Amass warning: ${data.toString()}`);
    });

    amass.on('close', (code) => {
      writeFileSync(join(outputDir, `amass-${safeName}.txt`), output);
      console.log(`      📁 Amass output saved to: amass-${safeName}.txt`);
      resolve(subdomains);
    });

    amass.on('error', (error) => {
      console.error(`      ❌ Amass error: ${error.message}`);
      console.log(`      💡 Make sure amass is installed and in PATH`);
      resolve([]);
    });
  });
}

async function runHttpx(subdomains: string[], outputDir: string, safeName: string): Promise<any[]> {
  return new Promise((resolve) => {
    if (subdomains.length === 0) {
      resolve([]);
      return;
    }

    console.log(`      🌐 Running: httpx -l ${subdomains.length} subdomains -silent -title -tech-detect -status-code`);
    
    const httpx = spawn('httpx', [
      '-silent',
      '-title',
      '-tech-detect',
      '-status-code',
      '-json'
    ], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    const aliveHosts: any[] = [];

    httpx.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter((line: string) => line.trim());
      lines.forEach((line: string) => {
        try {
          const result = JSON.parse(line);
          aliveHosts.push(result);
          process.stdout.write(`      ✅ ${result.url} [${result.status_code}] ${result.title || 'No title'}\n`);
        } catch (e) {
          // Ignore non-JSON lines
        }
      });
      output += data.toString();
    });

    httpx.stderr.on('data', (data) => {
      console.error(`      ⚠️  httpx warning: ${data.toString()}`);
    });

    httpx.on('close', (code) => {
      writeFileSync(join(outputDir, `httpx-${safeName}.json`), output);
      console.log(`      📁 httpx output saved to: httpx-${safeName}.json`);
      resolve(aliveHosts);
    });

    httpx.on('error', (error) => {
      console.error(`      ❌ httpx error: ${error.message}`);
      console.log(`      💡 Make sure httpx is installed and in PATH`);
      resolve([]);
    });

    // Send subdomains to stdin
    httpx.stdin.write(subdomains.join('\n'));
    httpx.stdin.end();
  });
}

async function runTechDetection(hosts: any[], outputDir: string, safeName: string): Promise<Record<string, any[]>> {
  // Technology detection is already handled by httpx
  const techResults: Record<string, any[]> = {};
  
  hosts.forEach(host => {
    if (host.tech) {
      const hostname = host.url ? new URL(host.url).hostname : '';
      techResults[hostname] = host.tech;
    }
  });

  return techResults;
}

async function runReconJob(db: Db, target: TargetDoc, jobId: string) {
  const rawDir = join(config.reconRawDir, jobId);
  await ensureDir(rawDir);

  console.log(`\n🔍 [recon] Starting reconnaissance on: ${target.asset.value}`);
  console.log(`   Program: ${target.program}`);
  console.log(`   Type: ${target.asset.type}`);

  // Sanitize filename for output files
  const sanitizeFilename = (value: string) => value.replace(/[*?"<>|]/g, '_').replace(/[/\\]/g, '_');
  const safeTargetValue = sanitizeFilename(target.asset.value);
  
  let discoveredHosts = 0;
  const reconResults = [];

  try {
    // Step 1: Subdomain Discovery with Subfinder
    console.log(`   📡 Running subdomain discovery...`);
    const subfinderResults = await runSubfinder(target.asset.value, rawDir, safeTargetValue);
    if (subfinderResults.length > 0) {
      console.log(`   ✅ Found ${subfinderResults.length} subdomains`);
      reconResults.push(...subfinderResults);
    } else {
      console.log(`   ⚠️  No subdomains found`);
    }

    // Step 2: Skip Amass (too slow)
    console.log(`   ⏭️  Skipping Amass (too slow), using Subfinder results only`);

    // Step 3: HTTP probing with httpx
    console.log(`   🌐 Checking which hosts are alive...`);
    const aliveHosts = await runHttpx(reconResults, rawDir, safeTargetValue);
    console.log(`   ✅ ${aliveHosts.length} hosts are alive`);

    // Step 4: Technology detection
    console.log(`   🔧 Detecting technologies...`);
    const techResults = await runTechDetection(aliveHosts, rawDir, safeTargetValue);
    
    // Store results in database
    if (aliveHosts.length > 0) {
      const normalizedResults = aliveHosts.map(host => ({
        targetId: target._id,
        subdomain: host.url ? new URL(host.url).hostname : null,
        ip: host.ip || null,
        ports: host.ports || [],
        tech: techResults[host.url ? new URL(host.url).hostname : ''] || [],
        fingerprints: {
          titles: host.title ? [host.title] : [],
          webservers: host.server ? [host.server] : [],
          country: host.country || null
        },
        sources: [{
          tool: 'recon-normalize',
          runId: jobId,
          details: {
            contributors: host.sources || [],
            pipeline: ['subfinder', 'amass', 'httpx']
          }
        }],
        isAlive: true,
        lastChecked: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: [],
        jobId
      }));

      await db.collection('recon_results').insertMany(normalizedResults);
      discoveredHosts = aliveHosts.length;
      
      console.log(`   🎯 Stored ${discoveredHosts} live hosts in database`);
    }

    // Update target last recon time
    await db.collection('targets').updateOne(
      { _id: toObjectId(target._id) },
      {
        $set: {
          lastReconAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      },
    );

  } catch (error) {
    console.error(`   ❌ Error during reconnaissance: ${(error as Error).message}`);
  }

  console.log(`   ✅ Reconnaissance complete for ${target.asset.value} - Found ${discoveredHosts} live hosts\n`);
  return discoveredHosts;
}

// Parallel reconnaissance processing with worker pool
async function runParallelRecon(db: Db, jobId: string, targets: TargetDoc[], maxConcurrent: number = 15) {
  let completed = 0;
  let totalHosts = 0;
  
  console.log(`\n🚀 Starting PARALLEL reconnaissance on ${targets.length} targets with ${maxConcurrent} workers...\n`);
  
  // Create worker pool
  const workers: Promise<number>[] = [];
  let currentIndex = 0;
  
  // Start initial batch of workers with staggered delays
  for (let i = 0; i < Math.min(maxConcurrent, targets.length); i++) {
    const target = targets[currentIndex++];
    if (!target) continue;
    
    // Add small delay to prevent overwhelming the system
    const delay = i * 200; // 200ms stagger between workers (recon is more resource intensive)
    
    workers.push(
      new Promise(resolve => setTimeout(resolve, delay))
        .then(() => runReconJob(db, target, jobId))
        .then(result => {
          completed++;
          totalHosts += result;
          console.log(`\n📊 Parallel Recon Progress: ${completed}/${targets.length} targets completed (${totalHosts} total hosts discovered)`);
          return result;
        })
        .catch(error => {
          completed++;
          console.error(`\n❌ Recon failed for target: ${error.message}`);
          return 0;
        })
    );
  }
  
  // Process remaining targets as workers complete
  while (currentIndex < targets.length) {
    // Wait for at least one worker to complete
    const completedWorkerIndex = await Promise.race(
      workers.map((worker, index) => worker.then(() => index).catch(() => index))
    );
    
    // Start new worker for next target
    const target = targets[currentIndex++];
    if (!target) continue;
    workers[completedWorkerIndex] = runReconJob(db, target, jobId)
      .then(result => {
        completed++;
        totalHosts += result;
        console.log(`\n📊 Parallel Recon Progress: ${completed}/${targets.length} targets completed (${totalHosts} total hosts discovered)`);
        return result;
      })
      .catch(error => {
        completed++;
        console.error(`\n❌ Recon failed for target: ${error.message}`);
        return 0;
      });
  }
  
  // Wait for all remaining workers to complete
  const finalResults = await Promise.allSettled(workers);
  const totalDiscovered = finalResults.reduce((sum, result) => {
    return sum + (result.status === 'fulfilled' ? result.value : 0);
  }, 0);
  
  return totalDiscovered;
}

async function main(): Promise<void> {
  await withDb(async (db) => {
    const job = await startJob(db, 'recon-drone', 'cli');
    try {
      const targets = await db
        .collection<TargetDoc>('targets')
        .find({ status: 'active' })
        .limit(100) // Increased limit for parallel processing
        .toArray();

      console.log(`\n🎯 Found ${targets.length} targets for parallel reconnaissance`);
      console.log(`💻 Machine resources: ${cpus().length} CPU cores available`);
      console.log(`🧠 Memory: ${Math.round(totalmem() / 1024 / 1024 / 1024)}GB total`);
      
      // Determine optimal concurrency for reconnaissance (more conservative than attacks)
      const cpuCores = cpus().length;
      const maxConcurrent = Math.min(15, Math.max(3, cpuCores)); // More conservative for recon
      
      console.log(`🎯 Using ${maxConcurrent} parallel reconnaissance workers (conservative for stability)`);
      
      const totalHosts = await runParallelRecon(db, job.jobId, targets, maxConcurrent);

      await finishJob(db, job, 'success', { processedTargets: targets.length, hostsInserted: totalHosts });
      console.log(`\n🎉 [recon] PARALLEL reconnaissance complete! ${targets.length} targets processed, ${totalHosts} hosts discovered`);
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
      console.log('[recon] Database connection closed');
      process.exit(process.exitCode || 0);
    });
  });
});
