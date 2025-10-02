#!/usr/bin/env ts-node
import { writeJsonFile } from '../lib/files.js';
import { config } from '../lib/config.js';
import { withDb } from '../lib/db.js';
import { startJob, finishJob } from '../lib/jobRuns.js';
import { normalizeAllPlatforms, type NormalizedTarget } from '../scope/parsers.js';
import type { Db } from 'mongodb';
import { resolve, join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';

function slugFromUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split('/').filter(Boolean);
    return segments[segments.length - 1] ?? parsed.hostname;
  } catch {
    return url;
  }
}

function adaptBugcrowd(raw: any): unknown {
  if (!Array.isArray(raw)) return raw;
  const programs = raw.map((entry) => {
    const targets = (entry.targets?.in_scope ?? []).map((scope: any) => ({
      category: scope.type ?? 'website',
      target: scope.target ?? scope.uri ?? '',
      instruction: scope.name ?? '',
    })).filter((t: any) => t.target);
    return {
      name: entry.name ?? slugFromUrl(entry.url ?? ''),
      slug: slugFromUrl(entry.url ?? ''),
      url: entry.url,
      targets,
    };
  }).filter((program) => program.targets.length);
  return { fetched_at: new Date().toISOString(), programs };
}

function adaptHackerOne(raw: any): unknown {
  if (!Array.isArray(raw)) return raw;
  const data = raw.map((entry) => ({
    attributes: {
      handle: entry.handle ?? slugFromUrl(entry.url ?? ''),
      name: entry.name ?? entry.handle ?? slugFromUrl(entry.url ?? ''),
      submission_state: entry.offers_bounty === false ? 'paused' : 'open',
      policy: entry.url,
      structured_scopes: (entry.targets?.in_scope ?? []).map((scope: any) => ({
        asset_identifier: scope.target ?? scope.uri ?? '',
        asset_type: (scope.type ?? 'url').toUpperCase(),
        eligible_for_bounty: true,
        instruction: scope.name ?? '',
      })).filter((s: any) => s.asset_identifier),
    },
  })).filter((entry) => entry.attributes.structured_scopes.length);
  return { data };
}

function adaptIntigriti(raw: any): unknown {
  if (!Array.isArray(raw)) return raw;
  const programs = raw.map((entry) => {
    const domains: any[] = [];
    const urls: any[] = [];
    const ips: any[] = [];
    for (const scope of entry.targets?.in_scope ?? []) {
      const identifier = scope.target ?? scope.uri ?? '';
      if (!identifier) continue;
      const record = {
        identifier,
        type: (scope.type ?? 'URL').toUpperCase(),
        description: scope.name ?? '',
      };
      if (record.type.includes('CIDR') || record.type === 'IP' || /\d+\.\d+/.test(identifier)) {
        ips.push({ identifier, type: 'CIDR', description: scope.name ?? '' });
      } else if (record.type === 'DOMAIN' || identifier.includes('.')) {
        domains.push({ identifier, type: 'DOMAIN', description: scope.name ?? '' });
      } else {
        urls.push({ identifier, type: 'URL', description: scope.name ?? '' });
      }
    }
    return {
      programId: entry.id ?? entry.slug ?? slugFromUrl(entry.url ?? ''),
      name: entry.name ?? slugFromUrl(entry.url ?? ''),
      slug: entry.slug ?? slugFromUrl(entry.url ?? ''),
      status: entry.status ?? 'public',
      domains,
      urls,
      ips,
    };
  });
  return { programs };
}

async function fetchJson(url: string, source: string): Promise<unknown | null> {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      console.warn(`[scope] ${source} responded with ${response.status}`);
      return null;
    }
    return await response.json();
  } catch (error) {
    console.warn(`[scope] Failed to fetch ${source}: ${(error as Error).message}`);
    return null;
  }
}

// Mock data loading removed - only live data now

async function getSourceData(): Promise<{
  bugcrowd?: unknown;
  hackerone?: unknown;
  intigriti?: unknown;
}> {
  const sources: Record<string, { url: string; fixture: string; adapt: (raw: any) => unknown }> = {
    bugcrowd: { url: config.bugcrowdUrl, fixture: 'bugcrowd.json', adapt: adaptBugcrowd },
    hackerone: { url: config.hackeroneUrl, fixture: 'hackerone.json', adapt: adaptHackerOne },
    intigriti: { url: config.intigritiUrl, fixture: 'intigriti.json', adapt: adaptIntigriti },
  };

  const payload: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(sources)) {
    const live = await fetchJson(value.url, key);
    if (live) {
      payload[key] = value.adapt(live);
      console.log(`[scope] Successfully fetched live data from ${key}`);
    } else {
      console.warn(`[scope] Failed to fetch live data from ${key} - skipping`);
    }
  }

  return payload;
}

async function persistRaw(jobId: string, raw: Record<string, unknown>) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  await mkdir(config.scopeRawDir, { recursive: true });
  for (const [source, data] of Object.entries(raw)) {
    const filePath = join(config.scopeRawDir, `${timestamp}-${source}-${jobId}.json`);
    await writeJsonFile(filePath, data);
  }
}

async function upsertTargets(db: Db, targets: NormalizedTarget[]) {
  if (!targets.length) return { inserted: 0, skipped: 0 };

  const collection = db.collection<NormalizedTarget>('targets');
  const existingDocs = await collection
    .find({}, { projection: { program: 1, 'asset.value': 1 } })
    .toArray();

  const existingKeys = new Set(existingDocs.map((doc: any) => `${doc.program}:${doc.asset?.value ?? ''}`));
  const fresh: NormalizedTarget[] = [];

  for (const target of targets) {
    const key = `${target.program}:${target.asset.value ?? ''}`;
    if (existingKeys.has(key)) {
      continue;
    }
    existingKeys.add(key);
    fresh.push(target);
  }

  if (fresh.length) {
    await collection.insertMany(fresh);
  }

  return { inserted: fresh.length, skipped: targets.length - fresh.length };
}

async function main(): Promise<void> {
  try {
    await withDb(async (db) => {
      const job = await startJob(db, 'scope-intake', 'cli');
      try {
        console.log('[scope] Starting scope intake...');
        const raw = (await getSourceData()) as Record<string, unknown>;
        console.log('[scope] Raw data fetched, persisting...');
        await persistRaw(job.jobId, raw);

        console.log('[scope] Normalizing targets...');
        const normalized = normalizeAllPlatforms(raw) as NormalizedTarget[];
        const stats = await upsertTargets(db, normalized);
        console.log(`[scope] processed ${normalized.length} targets`, stats);
        await finishJob(db, job, 'success', stats);
      } catch (error) {
        console.error('[scope] Job failed:', (error as Error).message);
        await finishJob(db, job, 'failed', undefined, error as Error);
        throw error;
      }
    });
  } catch (error) {
    console.error('[scope] Fatal error:', (error as Error).message);
    if ((error as Error).message.includes('MongoDB connection failed')) {
      console.error('[scope] Make sure MongoDB is running on localhost:27017');
    }
    throw error;
  }
}

main().catch((error) => {
  console.error('Fatal error caught:', error);
  console.error('Error type:', typeof error);
  console.error('Error message:', error?.message);
  console.error('Error stack:', error?.stack);
  process.exitCode = 1;
}).finally(() => {
  // Close database connection
  import('../lib/db.js').then(({ closeDatabase }) => {
    closeDatabase().then(() => {
      console.log('[scope] Database connection closed');
      process.exit(process.exitCode || 0);
    });
  });
});
