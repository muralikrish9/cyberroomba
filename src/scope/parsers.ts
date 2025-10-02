import { z } from "zod";
import { targetSchema, stampMetadata } from "../schemas/index.js";

const normalizedTargetSchema = targetSchema.omit({ _id: true });

export type NormalizedTarget = z.infer<typeof normalizedTargetSchema>;
export type AssetType = NormalizedTarget["asset"]["type"];

interface BuildTargetInput {
  program: string;
  source: NormalizedTarget["source"];
  asset: {
    type: AssetType;
    value: string;
    scope?: NormalizedTarget["asset"]["scope"];
  };
  notes?: string | null;
  metadata?: Record<string, unknown>;
}

const cidrPattern = /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function inferAssetType(value: string): AssetType {
  const trimmed = value.trim();
  const lower = trimmed.toLowerCase();

  if (cidrPattern.test(lower)) {
    return "cidr";
  }
  if (ipPattern.test(lower)) {
    return "ip";
  }
  if (lower.startsWith("http://") || lower.startsWith("https://")) {
    return "url";
  }
  if (lower.includes("/")) {
    return "url";
  }
  if (lower.includes(" ")) {
    return "hostname";
  }
  if (lower.includes(".")) {
    return "domain";
  }
  return "hostname";
}

function buildTarget(input: BuildTargetInput): NormalizedTarget {
  const now = new Date().toISOString();
  const draft: Record<string, unknown> = {
    program: input.program,
    source: input.source,
    asset: input.asset,
    firstSeen: now,
    lastSeen: now,
    status: "active",
    metadata: input.metadata,
  };

  if (input.notes) {
    draft.notes = input.notes;
  }

  const stamped = stampMetadata(draft);
  return normalizedTargetSchema.parse(stamped);
}

const bugcrowdTargetSchema = z.object({
  category: z.string(),
  target: z.string(),
  instruction: z.string().optional(),
});

const bugcrowdProgramSchema = z.object({
  name: z.string(),
  slug: z.string(),
  url: z.string().url().optional(),
  targets: z.array(bugcrowdTargetSchema),
});

const bugcrowdResponseSchema = z.object({
  fetched_at: z.string().optional(),
  programs: z.array(bugcrowdProgramSchema),
});

export function parseBugcrowdScope(raw: unknown): NormalizedTarget[] {
  const parsed = bugcrowdResponseSchema.parse(raw);
  const timestamp = parsed.fetched_at ?? new Date().toISOString();

  return parsed.programs.flatMap((program) => {
    const programId = `bugcrowd:${program.slug}`;
    return program.targets.map((item) =>
      buildTarget({
        program: programId,
        source: "bugcrowd",
        asset: {
          type: inferAssetType(item.target),
          value: item.target.trim(),
          scope: "in-scope",
        },
        notes: item.instruction ?? null,
        metadata: {
          category: item.category,
          platformUrl: program.url,
          fetchedAt: timestamp,
        },
      }),
    );
  });
}

const h1StructuredScopeSchema = z.object({
  asset_identifier: z.string(),
  asset_type: z.string(),
  eligible_for_bounty: z.boolean().optional(),
  instruction: z.string().optional(),
});

const hackeroneProgramSchema = z.object({
  attributes: z.object({
    handle: z.string(),
    name: z.string(),
    submission_state: z.string(),
    policy: z.string().optional(),
    structured_scopes: z.array(h1StructuredScopeSchema).default([]),
  }),
});

const hackeroneResponseSchema = z.object({
  data: z.array(hackeroneProgramSchema),
});

export function parseHackerOneScope(raw: unknown): NormalizedTarget[] {
  const parsed = hackeroneResponseSchema.parse(raw);
  const now = new Date().toISOString();

  return parsed.data.flatMap((entry) => {
    const { handle, structured_scopes, submission_state, policy } = entry.attributes;
    const programId = `hackerone:${handle}`;
    const scopeState = submission_state === "open" ? "in-scope" : "out-of-scope";

    return structured_scopes.map((scope) =>
      buildTarget({
        program: programId,
        source: "hackerone",
        asset: {
          type: inferAssetType(scope.asset_identifier),
          value: scope.asset_identifier.trim(),
          scope: scopeState,
        },
        notes: scope.instruction ?? null,
        metadata: {
          assetType: scope.asset_type,
          bountyEligible: scope.eligible_for_bounty ?? false,
          policy,
          fetchedAt: now,
        },
      }),
    );
  });
}

const intigritiAssetSchema = z.object({
  identifier: z.string(),
  type: z.string(),
  description: z.string().optional(),
});

const intigritiProgramSchema = z.object({
  programId: z.string(),
  name: z.string(),
  slug: z.string(),
  status: z.string(),
  domains: z.array(intigritiAssetSchema).default([]),
  urls: z.array(intigritiAssetSchema).default([]),
  ips: z.array(intigritiAssetSchema).default([]),
});

const intigritiResponseSchema = z.object({
  programs: z.array(intigritiProgramSchema),
});

const typeMap: Record<string, AssetType> = {
  DOMAIN: "domain",
  URL: "url",
  CIDR: "cidr",
  IP: "ip",
};

function parseIntigritiAssets(
  programId: string,
  assets: z.infer<typeof intigritiAssetSchema>[],
  defaultType: AssetType,
  metadata: Record<string, unknown>,
): NormalizedTarget[] {
  return assets.map((asset) =>
    buildTarget({
      program: programId,
      source: "intigriti",
      asset: {
        type: typeMap[asset.type] ?? defaultType,
        value: asset.identifier.trim(),
        scope: "in-scope",
      },
      notes: asset.description ?? null,
      metadata,
    }),
  );
}

export function parseIntigritiScope(raw: unknown): NormalizedTarget[] {
  const parsed = intigritiResponseSchema.parse(raw);
  const now = new Date().toISOString();

  return parsed.programs.flatMap((program) => {
    const programId = `intigriti:${program.slug}`;
    const metadata = {
      programId: program.programId,
      status: program.status,
      fetchedAt: now,
    } as Record<string, unknown>;

    return [
      ...parseIntigritiAssets(programId, program.domains, "domain", metadata),
      ...parseIntigritiAssets(programId, program.urls, "url", metadata),
      ...parseIntigritiAssets(programId, program.ips, "cidr", metadata),
    ];
  });
}

export function normalizeAllPlatforms(inputs: {
  bugcrowd?: unknown;
  hackerone?: unknown;
  intigriti?: unknown;
}): NormalizedTarget[] {
  return [
    ...(inputs.bugcrowd ? parseBugcrowdScope(inputs.bugcrowd) : []),
    ...(inputs.hackerone ? parseHackerOneScope(inputs.hackerone) : []),
    ...(inputs.intigriti ? parseIntigritiScope(inputs.intigriti) : []),
  ];
}
