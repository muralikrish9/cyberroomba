import { Db } from 'mongodb';
import { randomUUID } from 'node:crypto';

export type JobRecord = {
  jobId: string;
  workflow: string;
  trigger: string;
  status: 'running' | 'success' | 'failed';
  startedAt: string;
  finishedAt?: string;
  stats?: Record<string, unknown>;
  error?: { message: string; stack?: string };
};

export async function startJob(db: Db, workflow: string, trigger = 'manual'): Promise<JobRecord> {
  const job: JobRecord = {
    jobId: randomUUID(),
    workflow,
    trigger,
    status: 'running',
    startedAt: new Date().toISOString(),
  };
  const now = new Date().toISOString();
  await db.collection('job_runs').insertOne({
    ...job,
    createdAt: now,
    updatedAt: now,
    tags: [],
  });
  return job;
}

export async function finishJob(
  db: Db,
  job: JobRecord,
  status: 'success' | 'failed',
  stats?: Record<string, unknown>,
  error?: Error,
): Promise<void> {
  const update: Record<string, unknown> = {
    status,
    finishedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  if (stats) update.stats = stats;
  if (error) {
    update.error = {
      message: error.message,
      ...(error.stack ? { stack: error.stack } : {}),
    };
  }
  await db.collection('job_runs').updateOne({ jobId: job.jobId }, { $set: update });
}
