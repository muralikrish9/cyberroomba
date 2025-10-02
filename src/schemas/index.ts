import { z } from "zod";

const assetTypes = ["domain", "cidr", "ip", "hostname", "url"] as const;
const scopeStates = ["in-scope", "out-of-scope", "testing"] as const;
const targetStatuses = ["active", "snoozed", "retired"] as const;
const targetSources = ["bugcrowd", "hackerone", "intigriti", "manual", "other"] as const;
const serviceProtocols = ["tcp", "udp"] as const;
const severityLevels = ["critical", "high", "medium", "low", "info"] as const;
const confidenceLevels = ["confirmed", "suspected", "needs-review"] as const;
const vulnStatuses = ["open", "triaged", "mitigated", "closed"] as const;
const reportStatuses = ["draft", "submitted", "triaged", "resolved", "duplicated"] as const;
const jobTriggers = ["cron", "manual", "webhook", "event"] as const;
const jobStatuses = ["queued", "running", "success", "failed"] as const;
const artifactTypes = ["file", "url", "note"] as const;

const isoDate = z.string().datetime({ offset: true });
const recordAny = () => z.record(z.string(), z.any());

const baseDocumentSchema = z.object({
  createdAt: isoDate,
  updatedAt: isoDate,
  tags: z.array(z.string()).default([]),
});

export const targetAssetSchema = z.object({
  type: z.enum(assetTypes),
  value: z.string(),
  scope: z.enum(scopeStates).optional(),
});

export const targetSchema = z
  .object({
    _id: z.any().optional(),
    program: z.string(),
    source: z.enum(targetSources),
    asset: targetAssetSchema,
    firstSeen: isoDate,
    lastSeen: isoDate,
    status: z.enum(targetStatuses),
    notes: z.string().optional(),
    metadata: recordAny().optional(),
  })
  .merge(baseDocumentSchema);

const portSchema = z.object({
  port: z.number().int().min(1).max(65535),
  protocol: z.enum(serviceProtocols),
  service: z.string().optional(),
  product: z.string().optional(),
});

const techSchema = z.object({
  name: z.string(),
  version: z.string().optional(),
  categories: z.array(z.string()).optional(),
});

const sourceSchema = z.object({
  tool: z.string(),
  runId: z.string(),
  details: recordAny().optional(),
});

export const reconResultSchema = z
  .object({
    _id: z.any().optional(),
    targetId: z.any(),
    subdomain: z.string().optional(),
    ip: z.string().optional(),
    ports: z.array(portSchema).default([]),
    tech: z.array(techSchema).default([]),
    fingerprints: recordAny().optional(),
    sources: z.array(sourceSchema).min(1),
    isAlive: z.boolean(),
    lastChecked: isoDate,
  })
  .merge(baseDocumentSchema);

const cveSchema = z.object({
  id: z.string(),
  cvss: z
    .object({
      baseScore: z.number(),
      vector: z.string().optional(),
      version: z.string().optional(),
    })
    .optional(),
});

export const vulnerabilitySchema = z
  .object({
    _id: z.any().optional(),
    reconId: z.any(),
    source: z.string(),
    scannerFindingId: z.string().optional(),
    title: z.string(),
    severity: z.enum(severityLevels),
    confidence: z.enum(confidenceLevels),
    category: z.string().optional(),
    description: z.string().optional(),
    evidence: recordAny().optional(),
    cves: z.array(cveSchema).default([]),
    remediation: z.string().optional(),
    status: z.enum(vulnStatuses),
    reportedAt: isoDate.optional(),
    resolvedAt: isoDate.optional(),
  })
  .merge(baseDocumentSchema);

const reportContentSchema = z.object({
  title: z.string(),
  body: z.string(),
});

const payoutSchema = z.object({
  currency: z.string().default("USD"),
  amount: z.number().nonnegative(),
});

export const reportSchema = z
  .object({
    _id: z.any().optional(),
    program: z.string(),
    vulnIds: z.array(z.any()).default([]),
    reportId: z.string().optional(),
    status: z.enum(reportStatuses),
    payout: payoutSchema.optional(),
    content: reportContentSchema,
    submittedAt: isoDate.optional(),
    updatedBy: z.string().optional(),
  })
  .merge(baseDocumentSchema);

export const jobRunSchema = z
  .object({
    _id: z.any().optional(),
    workflow: z.string(),
    trigger: z.enum(jobTriggers),
    status: z.enum(jobStatuses),
    startedAt: isoDate,
    finishedAt: isoDate.optional(),
    durationMs: z.number().nonnegative().optional(),
    error: z
      .object({
        message: z.string(),
        stack: z.string().optional(),
        nodeId: z.string().optional(),
      })
      .optional(),
    stats: recordAny().optional(),
    artifacts: z
      .array(
        z.object({
          label: z.string(),
          path: z.string(),
          type: z.enum(artifactTypes).default("file"),
        })
      )
      .default([]),
  })
  .merge(baseDocumentSchema);

export const schemas = {
  targets: targetSchema,
  reconResults: reconResultSchema,
  vulnerabilities: vulnerabilitySchema,
  reports: reportSchema,
  jobRuns: jobRunSchema,
};

export type Target = z.infer<typeof targetSchema>;
export type ReconResult = z.infer<typeof reconResultSchema>;
export type Vulnerability = z.infer<typeof vulnerabilitySchema>;
export type Report = z.infer<typeof reportSchema>;
export type JobRun = z.infer<typeof jobRunSchema>;

export function stampMetadata<T extends Partial<z.infer<typeof baseDocumentSchema>>>(
  input: Omit<T, "createdAt" | "updatedAt"> & { tags?: string[] },
): z.infer<typeof baseDocumentSchema> & Omit<T, "createdAt" | "updatedAt"> {
  const now = new Date().toISOString();
  const tags = input.tags ?? [];
  return {
    ...input,
    tags,
    createdAt: (input as any).createdAt ?? now,
    updatedAt: now,
  } as z.infer<typeof baseDocumentSchema> & Omit<T, "createdAt" | "updatedAt">;
}
