import { z } from "zod";
import type { Vulnerability } from "../schemas/index.js";

const cveItemSchema = z.object({
  cve: z.object({
    CVE_data_meta: z.object({ ID: z.string() }),
    description: z
      .object({ description_data: z.array(z.object({ value: z.string() })) })
      .optional(),
  }),
  configurations: z
    .object({
      nodes: z
        .array(
          z.object({
            cpe_match: z
              .array(
                z.object({
                  vulnerable: z.boolean().optional(),
                  cpe23Uri: z.string(),
                  versionStartIncluding: z.string().optional(),
                  versionEndIncluding: z.string().optional(),
                }),
              )
              .optional(),
          }),
        )
        .optional(),
    })
    .optional(),
  impact: z
    .object({
      baseMetricV3: z
        .object({
          cvssV3: z
            .object({
              baseScore: z.number().optional(),
              vectorString: z.string().optional(),
            })
            .optional(),
        })
        .optional(),
    })
    .optional(),
});

const nvdFeedSchema = z.object({
  CVE_Items: z.array(cveItemSchema),
});

export type NvdFeed = z.infer<typeof nvdFeedSchema>;

export function parseNvdFeed(raw: unknown): NvdFeed | null {
  const parsed = nvdFeedSchema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

type CveDetail = {
  id: string;
  baseScore?: number;
  vector?: string;
  cpes: string[];
};

export function buildCveIndex(feed: NvdFeed | null): Map<string, CveDetail> {
  const map = new Map<string, CveDetail>();
  if (!feed) return map;

  feed.CVE_Items.forEach((item) => {
    const id = item.cve.CVE_data_meta.ID;
    const baseScore = item.impact?.baseMetricV3?.cvssV3?.baseScore;
    const vector = item.impact?.baseMetricV3?.cvssV3?.vectorString;
    const cpes: string[] = [];
    item.configurations?.nodes?.forEach((node) => {
      node.cpe_match?.forEach((cpe) => {
        if (cpe.vulnerable) {
          cpes.push(cpe.cpe23Uri);
        }
      });
    });
    const detail: CveDetail = { id, cpes };
    if (typeof baseScore === "number") detail.baseScore = baseScore;
    if (vector) detail.vector = vector;
    map.set(id, detail);
  });

  return map;
}

export function enrichVulnerabilitiesWithNvd(
  vulns: Vulnerability[],
  index: Map<string, CveDetail>,
): Vulnerability[] {
  return vulns.map((finding) => {
    if (!finding.cves?.length) return finding;

    const enriched = finding.cves.map((entry) => {
      const detail = index.get(entry.id);
      if (!detail) return entry;

      const baseScore = detail.baseScore ?? entry.cvss?.baseScore;
      if (typeof baseScore !== "number") {
        return entry;
      }

      return {
        id: entry.id,
        cvss: {
          baseScore,
          vector: detail.vector ?? entry.cvss?.vector,
          version: entry.cvss?.version ?? "3.x",
        },
      };
    });

    return {
      ...finding,
      cves: enriched,
    };
  });
}

function parseCpe(cpe: string): { vendor?: string; product?: string } | null {
  const parts = cpe.split(":");
  if (parts.length < 5) return null;
  const result: { vendor?: string; product?: string } = {};
  if (parts[3]) result.vendor = parts[3];
  if (parts[4]) result.product = parts[4];
  return result;
}

export type TechFingerprint = {
  name: string;
  version?: string;
};

export function suggestCvesFromTech(
  tech: TechFingerprint[],
  index: Map<string, CveDetail>,
): Array<{ tech: TechFingerprint; cve: CveDetail }> {
  const suggestions: Array<{ tech: TechFingerprint; cve: CveDetail }> = [];

  tech.forEach((fingerprint) => {
    const normalizedName = fingerprint.name.toLowerCase();
    index.forEach((detail) => {
      detail.cpes.forEach((cpe) => {
        const parsed = parseCpe(cpe);
        if (!parsed?.product) return;
        if (normalizedName.includes(parsed.product.toLowerCase())) {
          suggestions.push({ tech: fingerprint, cve: detail });
        }
      });
    });
  });

  return suggestions;
}

export const CveMatcher = {
  parseNvdFeed,
  buildCveIndex,
  enrichVulnerabilitiesWithNvd,
  suggestCvesFromTech,
};
