import { z } from "zod";
import { vulnerabilitySchema, stampMetadata } from "../schemas/index.js";
import type { Vulnerability } from "../schemas/index.js";

const nucleiSchema = z.array(
  z.object({
    templateID: z.string(),
    info: z.object({
      name: z.string(),
      severity: z.string().optional(),
      description: z.string().optional(),
      reference: z.array(z.string()).optional(),
      cve: z.string().optional(),
      tags: z.array(z.string()).optional(),
      "cvss-score": z.number().optional(),
    }),
    host: z.string(),
    "matched-at": z.string().optional(),
    request: z.string().optional(),
    response: z.string().optional(),
    timestamp: z.string().optional(),
  }),
);

const nmapSchema = z.object({
  host: z.string(),
  ports: z
    .array(
      z.object({
        port: z.number(),
        service: z.string().optional(),
        product: z.string().optional(),
        version: z.string().optional(),
        script: z
          .object({
            vulners: z
              .array(
                z.object({
                  id: z.string(),
                  cvss: z.number().optional(),
                  description: z.string().optional(),
                }),
              )
              .optional(),
          })
          .optional(),
      }),
    )
    .default([]),
});

type Severity = "critical" | "high" | "medium" | "low" | "info";

type BaseParams = {
  reconId: string;
  source: string;
  title: string;
  severity: Severity;
  confidence: "confirmed" | "suspected" | "needs-review";
  description?: string;
  evidence?: Record<string, unknown>;
  cves?: Vulnerability["cves"];
  category?: string;
  remediation?: string;
};

function normalizeSeverity(raw?: string): Severity {
  const normalized = (raw ?? "medium").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
    return normalized as Severity;
  }
  return "medium";
}

function severityFromCvss(score?: number): Severity {
  if (typeof score !== "number") return "medium";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

function pruneEmpty(obj: Record<string, unknown>) {
  Object.keys(obj).forEach((key) => {
    const value = obj[key];
    if (value === undefined || value === null || value === "") {
      delete obj[key];
    }
  });
}

function baseVulnerability(params: BaseParams): Vulnerability {
  const base: Record<string, unknown> = {
    reconId: params.reconId,
    source: params.source,
    title: params.title,
    severity: params.severity,
    confidence: params.confidence,
    status: "open",
  };

  if (params.description) base.description = params.description;
  if (params.evidence && Object.keys(params.evidence).length) base.evidence = params.evidence;
  if (params.cves && params.cves.length) base.cves = params.cves;
  if (params.category) base.category = params.category;
  if (params.remediation) base.remediation = params.remediation;

  const stamped = stampMetadata(base as any);
  return vulnerabilitySchema.parse(stamped) as Vulnerability;
}

export type NucleiParseOptions = {
  reconId: string;
  jobId: string;
  raw: unknown;
};

export function parseNucleiResults(options: NucleiParseOptions): Vulnerability[] {
  const parsed = nucleiSchema.safeParse(options.raw);
  if (!parsed.success) return [];

  return parsed.data.map((finding) => {
    const severity = normalizeSeverity(finding.info.severity);
    const confidence = finding.info.cve ? "confirmed" : "needs-review";

    const cves = finding.info.cve
      ? (() => {
          const record: { id: string; cvss?: { baseScore: number; version?: string } } = {
            id: finding.info.cve!,
          };
          if (typeof finding.info["cvss-score"] === "number") {
            record.cvss = { baseScore: finding.info["cvss-score"] as number, version: "3.x" };
          }
          return [record];
        })()
      : [];

    const evidence: Record<string, unknown> = {
      host: finding.host,
      matchedAt: finding["matched-at"],
      request: finding.request,
      response: finding.response,
      templateId: finding.templateID,
      timestamp: finding.timestamp,
      references: finding.info.reference,
      jobId: options.jobId,
    };
    pruneEmpty(evidence);

    const payload: BaseParams = {
      reconId: options.reconId,
      source: "nuclei",
      title: finding.info.name,
      severity,
      confidence,
      evidence,
      cves,
    };

    if (finding.info.tags?.length) payload.category = finding.info.tags.join(", ");
    if (finding.info.description) payload.description = finding.info.description;

    return baseVulnerability(payload);
  });
}

export type NmapParseOptions = {
  reconId: string;
  jobId: string;
  raw: unknown;
};

export function parseNmapVulnerabilities(options: NmapParseOptions): Vulnerability[] {
  const parsed = nmapSchema.safeParse(options.raw);
  if (!parsed.success) return [];

  const results: Vulnerability[] = [];

  parsed.data.ports.forEach((port) => {
    const vulners = port.script?.vulners ?? [];
    vulners.forEach((entry) => {
      const severity = severityFromCvss(entry.cvss);
      const evidence: Record<string, unknown> = {
        host: parsed.data.host,
        port: port.port,
        service: port.service,
        product: port.product,
        version: port.version,
        jobId: options.jobId,
      };
      pruneEmpty(evidence);

      const cves = (() => {
        const record: { id: string; cvss?: { baseScore: number; version?: string } } = { id: entry.id };
        if (typeof entry.cvss === "number") {
          record.cvss = { baseScore: entry.cvss, version: "3.x" };
        }
        return [record];
      })();

      const payload: BaseParams = {
        reconId: options.reconId,
        source: "nmap",
        title: `${entry.id} on port ${port.port}`,
        severity,
        confidence: "suspected",
        evidence,
        cves,
      };

      const category = port.service ?? port.product;
      if (category) payload.category = category;
      if (entry.description) payload.description = entry.description;

      results.push(baseVulnerability(payload));
    });
  });

  return results;
}

export function mergeFindings(...lists: Vulnerability[][]): Vulnerability[] {
  const seen = new Set<string>();
  const merged: Vulnerability[] = [];

  lists.flat().forEach((finding) => {
    const key = `${finding.reconId}:${finding.source}:${finding.title}`;
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(finding);
  });

  return merged;
}

export const VulnerabilityParsers = {
  parseNucleiResults,
  parseNmapVulnerabilities,
  mergeFindings,
};
